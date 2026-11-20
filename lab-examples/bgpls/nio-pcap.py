#!/usr/bin/env python3
"""Framing for little-endian NIO synthetic DLT_NULL IPv4/IPv6 TCP captures.

This is not a network-packet analyzer. NIO emits fixed IPv6 headers, no IP
fragments, ordered TCP bytes, and synthetic checksums. Extension headers,
jumbograms, retransmissions, and other capture formats remain unsupported.
"""

import ipaddress
import struct


class CaptureError(AssertionError):
    """The capture does not match the qualified NIO packet format."""


def require(condition, message):
    if not condition:
        raise CaptureError(message)


def tcp_packet(packet):
    require(len(packet) >= 4, "truncated DLT_NULL family field")
    family = int.from_bytes(packet[:4], "little")
    if family == 2:
        require(len(packet) >= 44, "truncated IPv4/TCP packet")
        require(packet[4] >> 4 == 4, "DLT_NULL family does not match IPv4 version")
        ip_size = (packet[4] & 15) * 4
        require(ip_size >= 20 and 4 + ip_size + 20 <= len(packet), "invalid IPv4 header length")
        require(int.from_bytes(packet[6:8], "big") == len(packet) - 4, "invalid IPv4 total length")
        require(packet[13] == 6, "expected IPv4 TCP packet")
        require(int.from_bytes(packet[10:12], "big") & 0x3fff == 0, "fragmented IPv4 unsupported")
        version = 4
        source = str(ipaddress.IPv4Address(packet[16:20]))
        destination = str(ipaddress.IPv4Address(packet[20:24]))
    elif family == 24:
        #  NIO writes the fixed value 24, not the platform's AF_INET6.
        # The frame is synthesized by NIO; accepting an OS-specific value would
        # silently broaden this audit to an unqualified capture format.
        require(len(packet) >= 64, "truncated IPv6/TCP packet")
        require(packet[4] >> 4 == 6, "DLT_NULL family does not match IPv6 version")
        payload_length = int.from_bytes(packet[8:10], "big")
        require(payload_length != 0, "IPv6 jumbograms unsupported")
        require(payload_length >= 20 and len(packet) == 4 + 40 + payload_length, "invalid IPv6 payload length")
        require(packet[10] == 6, "expected direct IPv6 TCP; extension headers and other protocols unsupported")
        ip_size, version = 40, 6
        source = str(ipaddress.IPv6Address(packet[12:28]))
        destination = str(ipaddress.IPv6Address(packet[28:44]))
    else:
        raise CaptureError(f"unsupported NIO DLT_NULL family: {family}")
    tcp = 4 + ip_size
    source_port, destination_port, sequence = struct.unpack_from("!HHI", packet, tcp)
    tcp_size = (packet[tcp + 12] >> 4) * 4
    require(tcp_size >= 20 and tcp + tcp_size <= len(packet), "invalid TCP header length")
    source_text = source if version == 4 else f"[{source}]"
    destination_text = destination if version == 4 else f"[{destination}]"
    return {
        "stream_key": (version, source, source_port, destination, destination_port),
        "stream": f"{source_text}:{source_port}->{destination_text}:{destination_port}",
        "family": version, "source": source, "destination": destination,
        "source_port": source_port, "destination_port": destination_port,
        "sequence": sequence, "flags": packet[tcp + 13], "payload": packet[tcp + tcp_size:],
    }


def tcp_packets(data):
    require(len(data) >= 24 and data[:4] == b"\xd4\xc3\xb2\xa1", "expected little-endian PCAP")
    major, minor, _, _, snaplen, linktype = struct.unpack_from("<HHIIII", data, 4)
    require((major, minor, linktype) == (2, 4, 0), "expected PCAP 2.4 BSD loopback link type")
    offset, index = 24, 0
    while offset < len(data):
        require(offset + 16 <= len(data), "truncated PCAP record header")
        seconds, micros, captured, original = struct.unpack_from("<IIII", data, offset)
        offset += 16
        require(micros < 1_000_000, "invalid PCAP microsecond timestamp")
        require(captured == original and captured <= snaplen, "truncated PCAP packet")
        require(offset + captured <= len(data), "truncated PCAP record data")
        item = tcp_packet(data[offset:offset + captured])
        offset += captured
        index += 1
        item.update(packet=index, timestamp_us=seconds * 1_000_000 + micros)
        yield item


def append_payload(streams, packet):
    """Keep families, addresses, and directions distinct before assembling BGP."""
    stream = streams.setdefault(packet["stream_key"], {"next": None, "buffer": bytearray()})
    sequence, flags, payload = packet["sequence"], packet["flags"], packet["payload"]
    if payload or flags & 3:
        if stream["next"] is not None:
            require(sequence == stream["next"], "TCP gap/retransmission/reordering unsupported in NIO capture")
        stream["next"] = (sequence + len(payload) + bool(flags & 2) + bool(flags & 1)) & 0xffffffff
    stream["buffer"].extend(payload)
    return stream["buffer"]
