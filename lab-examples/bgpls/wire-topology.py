#!/usr/bin/env python3
"""Independent, bounded BGP-LS identity audit for NIO's IPv4/IPv6 loopback PCAPs.

This is not a general packet analyzer: NIO emits ordered synthetic TCP packets,
without retransmissions or IP fragmentation. Reject other capture semantics
rather than silently assembling a plausible but incorrect topology. Path
attributes other than MP_REACH/MP_UNREACH remain opaque.
"""

import collections
import importlib.util
import ipaddress
from pathlib import Path
import struct


PCAP_SPEC = importlib.util.spec_from_file_location("bgpls_nio_pcap", Path(__file__).with_name("nio-pcap.py"))
PCAP = importlib.util.module_from_spec(PCAP_SPEC)
PCAP_SPEC.loader.exec_module(PCAP)


class WireError(AssertionError):
    """The capture or its topology evidence does not meet the lab contract."""


def require(condition, message):
    if not condition:
        raise WireError(message)


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, count):
        require(count >= 0 and self.offset + count <= len(self.data), "truncated wire field")
        value = self.data[self.offset:self.offset + count]
        self.offset += count
        return value

    def integer(self, count):
        return int.from_bytes(self.take(count), "big")

    def remaining(self):
        return len(self.data) - self.offset


def tlvs(data):
    reader = Reader(data)
    values = []
    while reader.remaining():
        kind, count = reader.integer(2), reader.integer(2)
        values.append((kind, reader.take(count)))
    return values


def encode_identity(values, protocol=None):
    #  Retain every unknown TLV, including repeated types and values.
    # Only the reserved IS-IS MT-ID bits have protocol-defined normalization.
    normalized = []
    for kind, value in values:
        if protocol in (1, 2) and kind == 263 and len(value) == 2:
            value = bytes([value[0] & 15, value[1]])
        normalized.append((kind, value))
    return "".join(f"{kind}:{len(value)}:{value.hex()};"
                   for kind, value in sorted(normalized, key=lambda item: (item[0], len(item[1]), item[1])))


def one(values, kind):
    matches = [value for code, value in values if code == kind]
    require(len(matches) == 1, f"expected exactly one descriptor {kind}")
    values.remove((kind, matches[0]))
    return matches[0]


def known_descriptors(values, widths):
    result = {}
    for kind, value in values:
        if kind in widths:
            require(kind not in result, f"duplicate known descriptor {kind}")
            width = widths[kind]
            require(width is None or len(value) == width, f"invalid descriptor {kind} width")
            result[kind] = value
    return result


def node_identity(data, protocol):
    values = tlvs(data)
    require(len({kind for kind, _ in values}) == len(values), "duplicate node descriptor")
    fields = known_descriptors(values, {512: 4, 513: 4, 514: 4, 515: None})
    router = fields.get(515)
    require(protocol not in range(1, 7) or router is not None, "missing IGP Router-ID")
    display = "?"
    if router is not None:
        if protocol in (1, 2):
            require(len(router) == 6 or len(router) == 7 and router[-1] != 0, "invalid IS-IS Router-ID")
            display = ".".join(router[index:index + 2].hex() for index in (0, 2, 4))
            if len(router) == 7:
                display += "." + router[6:].hex()
        elif protocol in (3, 6):
            require(len(router) in (4, 8), "invalid OSPF Router-ID")
            display = str(ipaddress.IPv4Address(router[:4]))
            if len(router) == 8:
                suffix = (str(ipaddress.IPv4Address(router[4:])) if protocol == 3
                          else str(int.from_bytes(router[4:], "big")))
                display += ":" + suffix
        else:
            display = "opaque:" + router.hex()
    # Deprecated 513 is retained in raw wire evidence, but is not identity.
    return encode_identity([(kind, value) for kind, value in values if kind != 513]), display


def interface_display(fields, local):
    codes = (259, 261) if local else (260, 262)
    addresses = [str(ipaddress.ip_address(fields[code])) for code in codes if code in fields]
    if addresses:
        return ",".join(addresses)
    if 258 in fields:
        start = 0 if local else 4
        return "id:" + str(int.from_bytes(fields[258][start:start + 4], "big"))
    return "?"


def parse_nlris(data):
    """Return complete wire records with Swift-compatible canonical identity keys."""
    reader = Reader(data)
    records = []
    while reader.remaining():
        kind, size = reader.integer(2), reader.integer(2)
        raw = reader.take(size)
        record = {"nlri_type": kind, "wire_hex": (struct.pack("!HH", kind, size) + raw).hex(),
                  "ipv6_link_descriptors": [], "multi_topology_id": None}
        if kind not in (1, 2, 3, 4):
            record.update(key=f"unknown:{kind}:{raw.hex()}", display=f"unknown type={kind}")
            records.append(record)
            continue
        body = Reader(raw)
        protocol, instance = body.integer(1), body.integer(8)
        descriptors = tlvs(body.take(body.remaining()))
        local_key, local = node_identity(one(descriptors, 256), protocol)
        domain = f"{protocol}:{instance}"
        if kind == 1:
            key = f"node:{domain}:local[{local_key}]:additional[{encode_identity(descriptors)}]"
            display = f"node {local}"
        elif kind == 2:
            remote_key, remote = node_identity(one(descriptors, 257), protocol)
            fields = known_descriptors(descriptors, {258: 8, 259: 4, 260: 4, 261: 16, 262: 16, 263: 2})
            key = (f"link:{domain}:local[{local_key}]:remote[{remote_key}]"
                   f":descriptors[{encode_identity(descriptors, protocol)}]")
            display = f"link {local} {interface_display(fields, True)} → {remote} {interface_display(fields, False)}"
            record["ipv6_link_descriptors"] = [code for code in (261, 262) if code in fields]
        else:
            fields = known_descriptors(descriptors, {263: 2, 264: 1, 265: None})
            reachability = fields.get(265, b"")
            require(reachability, "missing reachability prefix length")
            length, width = reachability[0], 32 if kind == 3 else 128
            count = (length + 7) // 8
            require(length <= width and len(reachability) == count + 1, "invalid reachability prefix width")
            address = int.from_bytes(reachability[1:].ljust(width // 8, b"\0"), "big")
            network_type = ipaddress.IPv4Network if kind == 3 else ipaddress.IPv6Network
            network = network_type((address, length), strict=False)
            canonical = bytes([length]) + network.network_address.packed[:count]
            descriptors = [(code, canonical if code == 265 else value) for code, value in descriptors]
            namespace = "prefix" if kind == 3 else "prefix6"
            key = f"{namespace}:{domain}:local[{local_key}]:descriptors[{encode_identity(descriptors, protocol)}]"
            display = f"prefix {network} node {local}"
        if kind in (2, 3, 4) and 263 in fields:
            mask = 0x0fff if protocol in (1, 2) else 0xffff
            record["multi_topology_id"] = int.from_bytes(fields[263], "big") & mask
        record.update(key=key, display=display, protocol_id=protocol, identifier=instance)
        records.append(record)
    return records


def update_events(body):
    reader = Reader(body)
    reader.take(reader.integer(2))  # Classic IPv4 withdrawals are outside this lab audit.
    attributes = Reader(reader.take(reader.integer(2)))
    multiprotocol = {}
    while attributes.remaining():
        flags, kind = attributes.integer(1), attributes.integer(1)
        value = attributes.take(attributes.integer(2 if flags & 16 else 1))
        if kind not in (14, 15):
            continue
        require(kind not in multiprotocol, f"duplicate MP attribute {kind}")
        attribute = Reader(value)
        afi, safi = attribute.integer(2), attribute.integer(1)
        if kind == 14:
            attribute.take(attribute.integer(1))
            attribute.take(1)  # Reserved octet, not a second NLRI count.
        if (afi, safi) == (16388, 71):
            multiprotocol[kind] = parse_nlris(attribute.take(attribute.remaining()))
        else:
            multiprotocol[kind] = []
    # Match LSRIB.apply(update:): reachability is applied before withdrawals.
    return [(operation, record) for kind, operation in ((14, "upsert"), (15, "withdraw"))
            for record in multiprotocol.get(kind, [])]


def update_next_hops(body):
    """Retain MP_REACH encoding independently of the TCP transport family."""
    reader = Reader(body)
    reader.take(reader.integer(2))
    attributes = Reader(reader.take(reader.integer(2)))
    result = []
    while attributes.remaining():
        flags, kind = attributes.integer(1), attributes.integer(1)
        value = attributes.take(attributes.integer(2 if flags & 16 else 1))
        if kind != 14:
            continue
        attribute = Reader(value)
        afi, safi = attribute.integer(2), attribute.integer(1)
        next_hop = attribute.take(attribute.integer(1))
        attribute.take(1)
        #  An IPv6 TCP session can carry a different next-hop encoding;
        # record all evidence, including a 32-byte IPv6 pair, without relabeling.
        encoding = {4: "ipv4", 16: "ipv6", 32: "ipv6-pair"}.get(len(next_hop), "opaque")
        width = 4 if len(next_hop) == 4 else 16
        addresses = ([str(ipaddress.ip_address(next_hop[offset:offset + width]))
                      for offset in range(0, len(next_hop), width)] if encoding != "opaque" else [])
        result.append({"afi": afi, "safi": safi, "length": len(next_hop), "encoding": encoding,
                       "addresses": addresses, "hex": next_hop.hex()})
    return result


def parse_capture(path):
    """Read a complete, closed NIO capture; retain direction and UPDATE ordering."""
    try:
        return parse_nio_capture(Path(path).read_bytes())
    except PCAP.CaptureError as error:
        raise WireError(str(error)) from error


def parse_nio_capture(data):
    #  Share transport framing with the completeness check, while this
    # independent auditor retains NLRI interpretation, keys, and UPDATE ordering.
    streams, events, updates = {}, [], []
    counts = collections.Counter()
    packet_count = 0
    for packet in PCAP.tcp_packets(data):
        packet_count = packet["packet"]
        stream_id = packet["stream"]
        pending = PCAP.append_payload(streams, packet)
        while len(pending) >= 19:
            require(pending[:16] == b"\xff" * 16, "invalid BGP marker")
            size, kind = struct.unpack_from("!HB", pending, 16)
            require(19 <= size <= 4096 and 1 <= kind <= 5, "invalid BGP header")
            if len(pending) < size:
                break
            message = bytes(pending[:size])
            del pending[:size]
            counts[kind] += 1
            if kind == 2:
                update = {"stream": stream_id, "packet": packet_count,
                          "timestamp_us": packet["timestamp_us"], "message_hex": message.hex()}
                updates.append(update)
                for operation, record in update_events(message[19:]):
                    events.append({"operation": operation, "record": record, "stream": stream_id,
                                   "update_index": len(updates) - 1})
    require(all(not stream["buffer"] for stream in streams.values()), "truncated BGP message")
    return {"records": packet_count, "bgp_messages_by_type": dict(counts), "events": events, "updates": updates}


def display_objects(state):
    """Never let a presentation set conceal two distinct complete NLRI keys."""
    objects = [record["display"] for record in state.values()]
    require(len(objects) == len(set(objects)), "distinct full NLRI keys collide in presentation")
    return set(objects)


def audit_capture(path, expected_objects, *, churn_objects=(), probe_objects=()):
    """Prove exact wire-key baseline, optional churn/probe cycles, and restoration.

    Native/watch comparisons remain independent. Expected display strings qualify
    this lab's baseline; all subsequent state transitions compare complete keys.
    Baseline prefix keys must survive every complete UPDATE after acquisition,
    including transitions between the requested churn/probe checkpoints.
    """
    capture = parse_capture(path)
    events = capture["events"]
    require(len({event["stream"] for event in events}) == 1, "expected one topology-producing TCP direction")
    state, states = {}, []
    baseline = None
    baseline_index = None
    seen_records = {}
    for index, event in enumerate(events):
        record, operation = event["record"], event["operation"]
        require(record["nlri_type"] in (1, 2, 3, 4), "unexpected unknown NLRI in qualified lab")
        #  Complete keys distinguish domains/MTs, but display text does
        # not. Qualify this lab's Level-2, instance-zero, default-topology IS-IS.
        require(record["protocol_id"] == 2 and record["identifier"] == 0,
                "unexpected protocol or instance in qualified lab")
        require(record["multi_topology_id"] in (None, 0), "non-default topology in qualified lab")
        key = record["key"]
        seen_records[key] = record
        if operation == "upsert":
            state[key] = record
        else:
            state.pop(key, None)
        objects = display_objects(state)
        states.append(frozenset(state))
        if baseline is None and objects == set(expected_objects):
            baseline, baseline_index = dict(state), index
    require(baseline is not None, "wire topology never reached the expected baseline")
    require(set(state) == set(baseline), "final full NLRI keys did not restore the baseline")
    require(any(record["nlri_type"] == 4 for record in baseline.values()), "no IPv6 topology prefix on wire")
    require(any(record["ipv6_link_descriptors"] for record in baseline.values()), "no IPv6 link descriptor on wire")
    #  Matching checkpoints alone can hide a withdrawn baseline prefix
    # that returns before the next checkpoint. Protect both families' full keys
    # at complete UPDATE boundaries, not TCP packets or intermediate NLRI states.
    # Empty/non-topology UPDATEs cannot change this state; the last topology
    # event still closes its UPDATE even when such messages follow it.
    baseline_prefixes = {key for key, record in baseline.items() if record["nlri_type"] in (3, 4)}
    for index in range(baseline_index, len(events)):
        update_index = events[index]["update_index"]
        if index + 1 < len(events) and events[index + 1]["update_index"] == update_index:
            continue
        missing = baseline_prefixes - states[index]
        require(not missing, f"baseline prefix keys missing after UPDATE {update_index}: {sorted(missing)}")
    checkpoints = [{"phase": "baseline", "event_index": baseline_index, "keys": sorted(baseline)}]
    cursor = baseline_index + 1

    def find_state(phase, keys):
        nonlocal cursor
        target = frozenset(keys)
        for index in range(cursor, len(states)):
            if states[index] == target:
                checkpoints.append({"phase": phase, "event_index": index, "keys": sorted(target)})
                cursor = index + 1
                return
        raise WireError(f"missing complete-key wire state: {phase}")

    if churn_objects:
        removed = {key for key, record in baseline.items() if record["display"] in set(churn_objects)}
        require(len(removed) == len(set(churn_objects)), "churn target missing from full-key baseline")
        find_state("links-withdrawn", set(baseline) - removed)
        find_state("links-restored", baseline)
    for probe in probe_objects:
        candidates = {key for key, record in seen_records.items() if record["display"] == probe}
        require(len(candidates) == 1, "probe must have one complete identity throughout the capture")
        require(not candidates.intersection(baseline), "probe unexpectedly belongs to baseline")
        for phase, keys in (("add", set(baseline) | candidates), ("withdraw", baseline),
                            ("readd", set(baseline) | candidates), ("restore", baseline)):
            find_state(f"{probe}: {phase}", keys)
    return {"records": capture["records"], "bgp_messages_by_type": capture["bgp_messages_by_type"],
            "nlri_events": len(events), "upserts": sum(event["operation"] == "upsert" for event in events),
            "withdrawals": sum(event["operation"] == "withdraw" for event in events),
            "final_records": [state[key] for key in sorted(state)], "checkpoints": checkpoints}
