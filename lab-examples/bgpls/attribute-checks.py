#!/usr/bin/env python3
"""Strict typed-attribute presentation/native adapters and scoped metric probes.

This module performs no I/O on import. MetricProbe requires explicitly injected,
bounded command callbacks; importing or testing it never connects to the lab.
"""

import copy
import importlib.util
import ipaddress
import math
from pathlib import Path
import re


IDENTITY = r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}"
NUMBER = r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
WATCH = re.compile(r"(?:bgpls: (?:[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3} )?)?WATCH (upsert|withdraw) (.*)")
# Current dumps name absent descriptors explicitly; retained captures may still
# use the historical question mark. Neither label belongs in watch identities.
NODE = re.compile(rf"(node {IDENTITY})(?: AS (?:[0-9]+|not-advertised|\?))?(?= |$)")
LINK = re.compile(rf"(link {IDENTITY} [^ ]+ → {IDENTITY} [^ ]+)(?= |$)")
PREFIX = re.compile(rf"(prefix [^ ]+ node {IDENTITY})(?= |$)")
FIELDS = {
    "node": ("name",),
    "link": ("igpMetric", "maximumLinkBandwidth", "maximumReservableBandwidth", "unreservedBandwidth"),
    "prefix": ("metric",),
}


class NativeAttributesPending(AssertionError):
    """A narrowly recognized native best-path selection gap, not invalid data."""


def _record(display, availability, attributes):
    return {"display": display, "availability": availability, "attributes": attributes}


def _identity(text, *, final=False):
    for kind, grammar in (("node", NODE), ("link", LINK), ("prefix", PREFIX)):
        match = grammar.match(text)
        if match is None:
            continue
        display = match[1]
        if kind == "node" and not final and match[0] != display:
            raise ValueError("watch node identities do not contain an AS field")
        if kind == "node" and final and " AS " not in match[0]:
            raise ValueError("final node records require the CLI's AS field")
        if kind == "link":
            for endpoint in (display.split()[2], display.split()[5]):
                addresses = endpoint.split(",")
                parsed = [ipaddress.ip_address(address) for address in addresses]
                if (len(parsed) not in (1, 2) or len({address.version for address in parsed}) != len(parsed)
                        or addresses != [str(address) for address in parsed]
                        or parsed != sorted(parsed, key=lambda address: address.version)):
                    raise ValueError("noncanonical or ambiguous link address presentation")
        elif kind == "prefix":
            prefix = display.split()[1]
            if str(ipaddress.ip_network(prefix)) != prefix:
                raise ValueError("noncanonical prefix presentation")
        return display, kind, text[match.end():]
    raise ValueError("unsupported or malformed lab object identity")


class _Cursor:
    def __init__(self, text):
        self.text = text
        self.position = 0

    def literal(self, value):
        if not self.text.startswith(value, self.position):
            raise ValueError(f"expected {value!r} at presentation offset {self.position}")
        self.position += len(value)

    def match(self, pattern):
        match = re.compile(pattern).match(self.text, self.position)
        if match is None:
            raise ValueError(f"invalid attribute value at presentation offset {self.position}")
        self.position = match.end()
        return match

    def unavailable(self):
        if self.text.startswith("unavailable", self.position):
            self.position += len("unavailable")
            return True
        return False

    def name(self):
        if self.unavailable():
            return None
        self.literal('"')
        result = []
        escapes = {"0": "\0", "t": "\t", "n": "\n", "r": "\r", '"': '"', "\\": "\\"}
        while self.position < len(self.text):
            char = self.text[self.position]
            self.position += 1
            if char == '"':
                if len(result) > 255:
                    raise ValueError("node name exceeds 255 ASCII octets")
                return "".join(result)
            if char == "\\":
                if self.position == len(self.text):
                    raise ValueError("incomplete node name escape")
                escaped = self.text[self.position]
                self.position += 1
                if escaped in escapes:
                    char = escapes[escaped]
                elif escaped == "u":
                    value = int(self.match(r"\{([0-9a-f]+)\}")[1], 16)
                    if value > 127 or value in (0, 9, 10, 13) or 32 <= value <= 126:
                        raise ValueError("noncanonical or non-ASCII node name escape")
                    char = chr(value)
                else:
                    raise ValueError("unsupported node name escape")
            elif not 32 <= ord(char) <= 126:
                raise ValueError("unescaped control or non-ASCII node name")
            result.append(char)
        raise ValueError("unterminated node name")

    def metric(self):
        if self.unavailable():
            return None
        value = int(self.match(r"0|[1-9][0-9]*")[0])
        if value > 0xFFFFFFFF:
            raise ValueError("metric exceeds UInt32")
        return value

    def bandwidth(self):
        if self.unavailable():
            return None
        value = float(self.match(NUMBER)[0])
        self.literal("B/s(")
        bits = float(self.match(NUMBER)[0])
        self.literal("bit/s)")
        if not math.isfinite(value) or not math.isfinite(bits) or bits != value * 8:
            raise ValueError("nonfinite bandwidth or inconsistent explicit bandwidth units")
        return value

    def priorities(self):
        if self.unavailable():
            return None
        self.literal("[")
        values = []
        for priority in range(8):
            self.literal(("," if priority else "") + f"{priority}:")
            value = self.bandwidth()
            if value is None:
                raise ValueError("an available priority collection must contain all eight values")
            values.append(value)
        self.literal("]")
        return values


def _parse_object(text, *, final=False):
    display, kind, suffix = _identity(text, final=final)
    cursor = _Cursor(suffix)
    cursor.literal(" attributes=")
    availability = cursor.match(r"absent|present|discarded")[0]
    if kind == "node":
        cursor.literal(" name=")
        values = {"name": cursor.name()}
    elif kind == "prefix":
        cursor.literal(" prefix-metric=")
        values = {"metric": cursor.metric()}
    else:
        values = {}
        for label, key, reader in (
            ("igp-metric", "igpMetric", cursor.metric),
            ("maximum-link-bandwidth", "maximumLinkBandwidth", cursor.bandwidth),
            ("maximum-reservable-bandwidth", "maximumReservableBandwidth", cursor.bandwidth),
            ("unreserved-bandwidth", "unreservedBandwidth", cursor.priorities),
        ):
            cursor.literal(f" {label}=")
            values[key] = reader()
    if cursor.position != len(suffix):
        raise ValueError("unexpected trailing attribute presentation")
    if availability != "present" and any(value is not None for value in values.values()):
        raise ValueError("absent/discarded attributes cannot expose usable values")
    return _record(display, availability, values)


def parse_line(line, final=False):
    """Parse a complete enriched watch upsert or bare final-RIB object line.

    Non-object output returns None. Once a line claims to be an object, malformed
    identity/attribute grammar fails closed rather than trimming arbitrary suffixes.
    """
    line = line.rstrip("\r\n")
    if "\r" in line or "\n" in line:
        raise ValueError("one presentation line required")
    if final:
        return _parse_object(line, final=True) if line.startswith(("node ", "link ", "prefix ")) else None
    match = WATCH.fullmatch(line)
    if match is None:
        if "WATCH upsert " in line or "WATCH withdraw " in line:
            raise ValueError("malformed watch line prefix")
        return None
    if match[1] == "withdraw":
        display, _, suffix = _identity(match[2])
        if suffix:
            raise ValueError("withdrawals must remain identity-only")
        return None
    return _parse_object(match[2])


def watch_events(text):
    """Preserve refreshes and attribute-only changes in complete wire order."""
    events = []
    for line in text.splitlines():
        match = WATCH.fullmatch(line)
        record = parse_line(line)
        if record is not None:
            events.append({"operation": "upsert", **record})
        elif match is not None and match[1] == "withdraw":
            display, _, _ = _identity(match[2])
            events.append({"operation": "withdraw", "display": display})
    return events


def watch_records(text):
    """Replay attributes as complete replacements under unchanged object identities."""
    records = {}
    # Live polling can race a partial file write. Only newline-terminated records
    # have been published; the closed-capture audit separately requires completion.
    complete = text[:text.rfind("\n") + 1]
    for event in watch_events(complete):
        display = event["display"]
        if event["operation"] == "withdraw":
            records.pop(display, None)
        else:
            records[display] = {key: value for key, value in event.items() if key != "operation"}
    return records


def final_records(text):
    records = {}
    for line in text.splitlines():
        record = parse_line(line, final=True)
        if record is not None:
            if record["display"] in records:
                raise ValueError("duplicate final-RIB identity")
            records[record["display"]] = record
    return records


def _helper(name):
    spec = importlib.util.spec_from_file_location("bgpls_attribute_" + name.replace("-", "_"),
                                                Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _number(value, *, metric=False, divisor=1):
    if value is None:
        return None
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("invalid native numeric projection")
    if metric and (type(value) is not int or value > 0xFFFFFFFF):
        raise ValueError("invalid native metric projection")
    return value if metric else value / divisor


def _projections(kind, data, *, producer):
    if data is None:
        return {field: None for field in FIELDS[kind]}
    if not isinstance(data, dict):
        raise ValueError("invalid native attribute object")
    if kind == "node":
        name = data.get("nodeName")
        if name is not None and (not isinstance(name, str) or not name.isascii() or len(name) > 255):
            raise ValueError("invalid native node name")
        return {"name": name}
    if kind == "prefix":
        return {"metric": _number(data.get("prefixMetric" if producer == "frr" else "metric"), metric=True)}
    divisor = 1 if producer == "frr" else 8
    raw = data.get("unreservedBandwidth" if producer == "frr" else "unreservedBw")
    priorities = None
    if raw is not None:
        if producer == "frr":
            if not isinstance(raw, list) or len(raw) != 8 or any(
                    not isinstance(item, dict) or set(item) != {f"classType{index}"}
                    for index, item in enumerate(raw)):
                raise ValueError("invalid FRR priority bandwidth schema")
            priorities = [item[f"classType{index}"] for index, item in enumerate(raw)]
        else:
            if not isinstance(raw, dict) or set(raw) != {f"priority{index}" for index in range(8)}:
                raise ValueError("invalid cEOS priority bandwidth schema")
            priorities = [raw[f"priority{index}"] for index in range(8)]
        priorities = [_number(value, divisor=divisor) for value in priorities]
        if any(value is None for value in priorities):
            raise ValueError("incomplete native priority bandwidth collection")
    return {
        "igpMetric": _number(data.get("igpMetric"), metric=True),
        "maximumLinkBandwidth": _number(data.get("maxLinkBandwidth" if producer == "frr" else "maxLinkBw"), divisor=divisor),
        "maximumReservableBandwidth": _number(data.get("maxResvLinkBandwidth" if producer == "frr" else "maxReservableLinkBw"), divisor=divisor),
        "unreservedBandwidth": priorities,
    }


def native_records(table, producer, asn=65001):
    """Use the pinned vendor schemas; never infer zeros from missing properties.

    Native availability describes whether the vendor exposes its attribute object,
    not raw wire flags. The independent PCAP audit remains authoritative for wire
    absence/discard. All six projections are compared only after schema validation.
    """
    result = {}
    if producer == "frr":
        verifier = _helper("verify")
        for key, paths in table["routes"].items():
            try:
                display, = verifier.native_objects({"routes": {key: paths}})
            except verifier.NativeSelectionPending as error:
                # Dynamic imports have distinct exception class identities.
                # Translate only this verifier's known convergence condition;
                # malformed schemas and ambiguous selected paths stay fatal.
                raise NativeAttributesPending(str(error)) from error
            selected, = [path for path in paths if path.get("valid") and path.get("bestpath")]
            data = selected.get("linkStateAttrs")
            kind = display.split()[0]
            result[display] = _record(display, "absent" if data is None else "present",
                                      _projections(kind, data, producer=producer))
    elif producer == "ceos":
        verifier = _helper("verify-ceos")
        for key, route in table["vrfs"]["default"]["bgpLsRoutes"].items():
            display, = verifier.native_ceos_objects({"vrfs": {"default": {"bgpLsRoutes": {key: route}}}}, asn)
            selected, = [path for path in route["paths"]
                         if path["routeType"].get("valid") and path["routeType"].get("active")]
            kind = display.split()[0]
            field = {"node": "bgpLsNodeAttributes", "link": "bgpLsLinkAttributes", "prefix": "bgpLsPrefixAttributes"}[kind]
            data = selected["routeDetail"].get(field)
            result[display] = _record(display, "absent" if data is None else "present",
                                      _projections(kind, data, producer=producer))
    else:
        raise ValueError("unknown producer")
    expected_count = len(table["routes"] if producer == "frr" else table["vrfs"]["default"]["bgpLsRoutes"])
    if len(result) != expected_count:
        raise ValueError("native attribute identities collide")
    return result


def expected_records(profile="ceos"):
    """Origin-aware baseline: producer vendor is not the originating node vendor."""
    if profile not in ("frr", "ceos"):
        raise ValueError("unknown lab profile")
    verifier = _helper("verify-ceos" if profile == "ceos" else "verify")
    names = {value: name for name, value in verifier.IDS.items()}
    result = {}
    objects = (verifier.expected_objects() if profile == "ceos" else
               verifier.expected_links() | verifier.expected_loopbacks() | {f"node {value}" for value in verifier.IDS.values()})
    for display in objects:
        kind = display.split()[0]
        if kind == "node":
            attrs = {"name": names[display.split()[1]]}
        elif kind == "prefix":
            attrs = {"metric": 10}
        else:
            ceos = names[display.split()[1]] == "edge-ceos"
            maximum, reservable = (125_000_000, 0) if ceos else (1_250_000, 1_250_000)
            attrs = {"igpMetric": 10, "maximumLinkBandwidth": maximum,
                     "maximumReservableBandwidth": reservable, "unreservedBandwidth": [reservable] * 8}
        result[display] = _record(display, "present", attrs)
    return result


class MetricProbe:
    """A deliberately narrow, reversible interface-metric transaction.

    Callbacks must honor their timeout keyword. No callbacks run until prepare or
    apply is called. The owner handles routing convergence and evidence persistence.
    Syntax references: docs.frrouting.org/en/stable-10.7/isisd.html and
    www.arista.com/en/um-eos/eos-is-is (isis metric / no isis metric).
    Only unscoped metrics on an explicitly Level-2-only interface are supported.
    """

    def __init__(self, producer, read_config, configure, read_metric, *, timeout=10, target_metric=20, record=None):
        if producer not in ("frr", "ceos"):
            raise ValueError("unknown metric-probe producer")
        if type(target_metric) is not int or not 1 <= target_metric <= 63:
            raise ValueError("probe metric must fit the shared conservative 1...63 range")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("command timeout must be bounded to 0...30 seconds")
        self.producer = producer
        self.node, self.interface = ("p1", "eth3") if producer == "frr" else ("edge-ceos", "Ethernet1")
        self.read_config, self.configure, self.read_metric = read_config, configure, read_metric
        self.timeout, self.target_metric = timeout, target_metric
        self.record = record
        self.evidence = []
        self.before = None
        self.original_metric = None
        self.original_line = None
        self.armed = False

    def _record(self, event, **data):
        evidence = {"producer": self.producer, "node": self.node, "interface": self.interface, **data}
        self.evidence.append({"event": event, **copy.deepcopy(evidence)})
        if self.record is not None:
            self.record(event, evidence)

    def _read(self):
        text = self.read_config(self.node, self.interface, timeout=self.timeout)
        if not isinstance(text, str):
            raise ValueError("metric probe requires textual running configuration")
        lines = text.splitlines()
        headers = [index for index, line in enumerate(lines) if line.strip() == f"interface {self.interface}"]
        if len(headers) != 1:
            raise ValueError("expected exactly the scoped interface stanza")
        commands = []
        for line in lines[headers[0] + 1:]:
            if line and not line[0].isspace():
                break
            value = line.strip()
            if value and not value.startswith("!"):
                commands.append(value)
        # Running configurations use different canonical spellings; match the
        # selected vendor rather than accepting either spelling indiscriminately.
        circuit_type = "isis circuit-type " + ("level-2-only" if self.producer == "frr" else "level-2")
        if (circuit_type not in commands
                or "isis network point-to-point" not in commands
                or ("ip router isis CORE" if self.producer == "frr" else "isis enable CORE") not in commands):
            raise ValueError("interface is not the qualified Level-2 point-to-point CORE interface")
        metrics = [line for line in commands if re.match(r"(?:no |default )?isis (?:ipv6 )?metric(?: |$)", line)]
        if len(metrics) > 1 or (metrics and not re.fullmatch(r"isis metric (?:0|[1-9][0-9]*)", metrics[0])):
            raise ValueError("unsupported or ambiguous existing metric configuration")
        return {"text": text, "commands": commands, "metric": metrics[0] if metrics else None}

    @staticmethod
    def _without_metric(state):
        return [command for command in state["commands"] if command != state["metric"]]

    def prepare(self):
        if self.before is not None:
            raise RuntimeError("metric probe has already been prepared")
        before = self._read()
        effective = self.read_metric(self.node, self.interface, timeout=self.timeout)
        configured = int(before["metric"].split()[-1]) if before["metric"] else 10
        if type(effective) is not int or effective != configured or effective == self.target_metric:
            raise ValueError("effective metric disagrees with configuration or is already the probe value")
        self.before, self.original_metric, self.original_line = before, effective, before["metric"]
        self._record("prepared", configuration=before["text"], effective_metric=effective,
                     explicit_metric=self.original_line, target_metric=self.target_metric)
        return self

    def _configure(self, command):
        commands = ["configure terminal", f"interface {self.interface}", command, "end"]
        self.configure(self.node, commands, timeout=self.timeout)

    def apply(self):
        if self.before is None:
            self.prepare()
        if self.armed:
            raise RuntimeError("metric probe is already armed")
        if self._read()["commands"] != self.before["commands"]:
            raise ValueError("interface configuration drift before metric change")
        self.armed = True
        try:
            self._record("armed", restore_command=self.original_line or "no isis metric")
            self._configure(f"isis metric {self.target_metric}")
            after = self._read()
            if (self._without_metric(after) != self._without_metric(self.before)
                    or after["metric"] != f"isis metric {self.target_metric}"):
                raise ValueError("metric change was not applied exactly")
            self._record("applied", configuration=after["text"])
        except BaseException as failure:
            try:
                self.restore()
            except BaseException as rollback:
                # Preserve both failures in the top-level evidence/error string;
                # callers must not publish success while rollback remains armed.
                raise RuntimeError(f"metric probe failed ({failure!r}); rollback also failed ({rollback!r})") from rollback
            raise
        return self

    def restore(self):
        if not self.armed:
            return
        current = self._read()
        if (self._without_metric(current) != self._without_metric(self.before)
                or current["metric"] not in (self.original_line, f"isis metric {self.target_metric}")):
            raise RuntimeError("configuration drift: refusing to overwrite an unowned metric change")
        if current["metric"] != self.original_line:
            self._record("restoring", command=self.original_line or "no isis metric")
            self._configure(self.original_line or "no isis metric")
        after = self._read()
        if (self._without_metric(after) != self._without_metric(self.before)
                or after["metric"] != self.original_line):
            raise RuntimeError("metric restoration failed; rollback remains armed")
        self.armed = False
        self._record("restored", configuration=after["text"], expected_effective_metric=self.original_metric)

    def __enter__(self):
        return self.apply()

    def __exit__(self, _kind, _value, _traceback):
        self.restore()
        return False
