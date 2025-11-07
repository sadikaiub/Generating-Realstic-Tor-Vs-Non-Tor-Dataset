#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_to_flows_advanced_timeout.py
PCAP -> flow CSV using Scapy, with idle-timeout, optional TCP fast-close,
and richer features (per-direction IAT & pktlen stats, TCP flag counters).

Usage terminal and select the path :
  python Scapy_Flow_Generation.py input.pcap output.csv \
      --timeout 120 --fast-close --sweep-every 50000

Install:
  pip install scapy
"""

import csv
import math
import argparse
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Optional

from scapy.all import PcapReader, IP, IPv6, TCP, UDP


# ---------- Tiny online stats helper ----------
@dataclass
class OnlineStats:
    n: int = 0
    mean: float = 0.0
    M2: float = 0.0
    minv: float = float("inf")
    maxv: float = float("-inf")

    def add(self, x: float):
        self.n += 1
        if x < self.minv:
            self.minv = x
        if x > self.maxv:
            self.maxv = x
        d = x - self.mean
        self.mean += d / self.n
        self.M2 += d * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.M2 / (self.n - 1)) if self.n > 1 else 0.0


# ---------- Flow record ----------
@dataclass
class Flow:
    # Identification (canonical A-B order)
    ip_a: str
    ip_b: str
    sport: int
    dport: int
    proto: int

    # Timing
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None

    # Totals
    total_pkts: int = 0
    total_bytes: int = 0

    # Direction anchor (first sender is "forward")
    fwd_ip: Optional[str] = None

    # Directional packet/byte counters
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # Packet-length stats
    pktlens: OnlineStats = field(default_factory=OnlineStats)      # overall
    fwd_pktlens: OnlineStats = field(default_factory=OnlineStats)
    bwd_pktlens: OnlineStats = field(default_factory=OnlineStats)

    # IAT stats
    iats: OnlineStats = field(default_factory=OnlineStats)         # overall
    fwd_iats: OnlineStats = field(default_factory=OnlineStats)
    bwd_iats: OnlineStats = field(default_factory=OnlineStats)
    _prev_ts_any: Optional[float] = None
    _prev_ts_fwd: Optional[float] = None
    _prev_ts_bwd: Optional[float] = None

    # TCP flag counters
    tcp_fin: int = 0
    tcp_syn: int = 0
    tcp_rst: int = 0
    tcp_psh: int = 0
    tcp_ack: int = 0
    tcp_urg: int = 0
    tcp_ece: int = 0
    tcp_cwr: int = 0

    def add_packet(self, ts: float, length: int, src_ip: str, tcp_flags: Optional[int] = None):
        if self.start_ts is None:
            self.start_ts = ts
            self.fwd_ip = src_ip
        self.end_ts = ts

        # global totals
        self.total_pkts += 1
        self.total_bytes += length
        self.pktlens.add(length)

        # overall IAT
        if self._prev_ts_any is not None:
            self.iats.add(ts - self._prev_ts_any)
        self._prev_ts_any = ts

        # direction split
        is_fwd = (src_ip == self.fwd_ip)
        if is_fwd:
            self.fwd_pkts += 1
            self.fwd_bytes += length
            self.fwd_pktlens.add(length)

            if self._prev_ts_fwd is not None:
                self.fwd_iats.add(ts - self._prev_ts_fwd)
            self._prev_ts_fwd = ts
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += length
            self.bwd_pktlens.add(length)

            if self._prev_ts_bwd is not None:
                self.bwd_iats.add(ts - self._prev_ts_bwd)
            self._prev_ts_bwd = ts

        # TCP flag counting (if applicable)
        if tcp_flags is not None:
            if tcp_flags & 0x01: self.tcp_fin += 1
            if tcp_flags & 0x02: self.tcp_syn += 1
            if tcp_flags & 0x04: self.tcp_rst += 1
            if tcp_flags & 0x08: self.tcp_psh += 1
            if tcp_flags & 0x10: self.tcp_ack += 1
            if tcp_flags & 0x20: self.tcp_urg += 1
            if tcp_flags & 0x40: self.tcp_ece += 1
            if tcp_flags & 0x80: self.tcp_cwr += 1

    def to_row(self) -> dict:
        duration = (self.end_ts - self.start_ts) if (self.start_ts is not None and self.end_ts is not None) else 0.0
        pps = (self.total_pkts / duration) if duration > 0 else 0.0
        bps = (self.total_bytes / duration) if duration > 0 else 0.0

        return {
            # Identification (5-tuple)
            "SrcIP": self.ip_a,
            "SrcPort": self.sport,
            "DstIP": self.ip_b,
            "DstPort": self.dport,
            "Proto": self.proto,

            # Timing
            "StartTime": self.start_ts or 0.0,
            "EndTime": self.end_ts or 0.0,
            "Duration": duration,

            # Volume & rates
            "TotalPackets": self.total_pkts,
            "TotalBytes": self.total_bytes,
            "PacketsPerSec": pps,
            "BytesPerSec": bps,

            # Directional basics
            "FwdPackets": self.fwd_pkts,
            "BwdPackets": self.bwd_pkts,
            "FwdBytes": self.fwd_bytes,
            "BwdBytes": self.bwd_bytes,

            # Packet length stats (overall + directional)
            "PktLenMin": 0 if self.pktlens.n == 0 else self.pktlens.minv,
            "PktLenMax": 0 if self.pktlens.n == 0 else self.pktlens.maxv,
            "PktLenMean": 0.0 if self.pktlens.n == 0 else self.pktlens.mean,
            "PktLenStd": 0.0 if self.pktlens.n < 2 else self.pktlens.std,

            "FwdPktLenMin": 0 if self.fwd_pktlens.n == 0 else self.fwd_pktlens.minv,
            "FwdPktLenMax": 0 if self.fwd_pktlens.n == 0 else self.fwd_pktlens.maxv,
            "FwdPktLenMean": 0.0 if self.fwd_pktlens.n == 0 else self.fwd_pktlens.mean,
            "FwdPktLenStd": 0.0 if self.fwd_pktlens.n < 2 else self.fwd_pktlens.std,

            "BwdPktLenMin": 0 if self.bwd_pktlens.n == 0 else self.bwd_pktlens.minv,
            "BwdPktLenMax": 0 if self.bwd_pktlens.n == 0 else self.bwd_pktlens.maxv,
            "BwdPktLenMean": 0.0 if self.bwd_pktlens.n == 0 else self.bwd_pktlens.mean,
            "BwdPktLenStd": 0.0 if self.bwd_pktlens.n < 2 else self.bwd_pktlens.std,

            # IAT (overall + directional)
            "IATCount": self.iats.n,
            "IATMin": 0.0 if self.iats.n == 0 else self.iats.minv,
            "IATMax": 0.0 if self.iats.n == 0 else self.iats.maxv,
            "IATMean": 0.0 if self.iats.n == 0 else self.iats.mean,
            "IATStd": 0.0 if self.iats.n < 2 else self.iats.std,

            "FwdIATCount": self.fwd_iats.n,
            "FwdIATMin": 0.0 if self.fwd_iats.n == 0 else self.fwd_iats.minv,
            "FwdIATMax": 0.0 if self.fwd_iats.n == 0 else self.fwd_iats.maxv,
            "FwdIATMean": 0.0 if self.fwd_iats.n == 0 else self.fwd_iats.mean,
            "FwdIATStd": 0.0 if self.fwd_iats.n < 2 else self.fwd_iats.std,

            "BwdIATCount": self.bwd_iats.n,
            "BwdIATMin": 0.0 if self.bwd_iats.n == 0 else self.bwd_iats.minv,
            "BwdIATMax": 0.0 if self.bwd_iats.n == 0 else self.bwd_iats.maxv,
            "BwdIATMean": 0.0 if self.bwd_iats.n == 0 else self.bwd_iats.mean,
            "BwdIATStd": 0.0 if self.bwd_iats.n < 2 else self.bwd_iats.std,

            # TCP flags
            "TCP_FIN": self.tcp_fin,
            "TCP_SYN": self.tcp_syn,
            "TCP_RST": self.tcp_rst,
            "TCP_PSH": self.tcp_psh,
            "TCP_ACK": self.tcp_ack,
            "TCP_URG": self.tcp_urg,
            "TCP_ECE": self.tcp_ece,
            "TCP_CWR": self.tcp_cwr,
        }


# ---------- Canonical bidirectional key ----------
def flow_key(src: str, dst: str, sport: int, dport: int, proto: int) -> Tuple[str, str, int, int, int]:
    """
    Make a canonical, direction-agnostic key so A->B and B->A are one flow.
    Keep lower (IP,port) pair first; handles IPv4/IPv6 as strings.
    """
    if (src, sport) <= (dst, dport):
        return (src, dst, sport, dport, proto)
    else:
        return (dst, src, dport, sport, proto)


# ---------- Internals ----------
def _start_new_flow(active: Dict[Tuple, Flow], k: Tuple[str, str, int, int, int]) -> Flow:
    a, b, pa, pb, pr = k
    fl = Flow(ip_a=a, ip_b=b, sport=pa, dport=pb, proto=pr)
    active[k] = fl
    return fl


def _close_flow(active: Dict[Tuple, Flow],
                last_seen: Dict[Tuple, float],
                done: List[Flow],
                k: Tuple,
                end_ts: Optional[float] = None):
    fl = active.pop(k, None)
    if fl is None:
        return
    if end_ts is not None:
        fl.end_ts = end_ts
    elif fl.end_ts is None and k in last_seen:
        fl.end_ts = last_seen[k]
    done.append(fl)
    last_seen.pop(k, None)


# ---------- PCAP -> flows with timeout ----------
def pcap_to_flows(pcap_path: str,
                  csv_path: str,
                  flow_timeout: float = 120.0,
                  fast_close: bool = True,
                  sweep_every: int = 50000):
    """
    - flow_timeout: idle seconds to split flows
    - fast_close:   close TCP flows immediately on FIN or RST (in addition to idle timeout)
    - sweep_every:  how many packets between idle sweeps (flush flows idle > timeout)
    """
    active: Dict[Tuple, Flow] = {}
    last_seen: Dict[Tuple, float] = {}
    done: List[Flow] = []

    packet_count = 0
    current_ts = 0.0

    with PcapReader(pcap_path) as rd:
        for pkt in rd:
            # timestamp & length
            try:
                ts = float(pkt.time)
                length = len(pkt)
                current_ts = ts
            except Exception:
                continue

            # IP layer
            if IP in pkt:
                ip = pkt[IP]
                src = ip.src
                dst = ip.dst
                proto = 6 if TCP in pkt else 17 if UDP in pkt else ip.proto
            elif IPv6 in pkt:
                ip = pkt[IPv6]
                src = ip.src
                dst = ip.dst
                proto = 6 if TCP in pkt else 17 if UDP in pkt else ip.nh
            else:
                continue  # non-IP

            # ports (0 for non TCP/UDP)
            tcp_flags = None
            if TCP in pkt:
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                tcp_flags = int(pkt[TCP].flags)
            elif UDP in pkt:
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
            else:
                sport = 0
                dport = 0

            k = flow_key(src, dst, sport, dport, proto)

            # If we’ve seen this flow before, check idle gap vs timeout
            if k in last_seen:
                idle = ts - last_seen[k]
                if idle > flow_timeout:
                    # Close the old segment and start a new one
                    _close_flow(active, last_seen, done, k, end_ts=last_seen[k])
                    _start_new_flow(active, k)

            # Create flow if new (or just flushed)
            if k not in active:
                _start_new_flow(active, k)

            # Update with this packet
            fl = active[k]
            fl.add_packet(ts, length, src, tcp_flags=tcp_flags)
            last_seen[k] = ts

            # Optional fast-close on TCP FIN/RST
            if fast_close and tcp_flags is not None:
                fin = tcp_flags & 0x01
                rst = tcp_flags & 0x04
                if fin or rst:
                    _close_flow(active, last_seen, done, k, end_ts=ts)

            # Periodic idle sweep to keep memory bounded
            packet_count += 1
            if packet_count % sweep_every == 0:
                cutoff = current_ts - flow_timeout
                to_close = [kk for kk, seen_ts in last_seen.items()
                            if seen_ts <= cutoff and kk in active]
                for kk in to_close:
                    _close_flow(active, last_seen, done, kk,
                                end_ts=last_seen.get(kk, current_ts))

    # EOF: flush remaining active flows
    for kk in list(active.keys()):
        _close_flow(active, last_seen, done, kk)

    # Write CSV
    fieldnames = [
        # IDs
        "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto",
        # Timing
        "StartTime", "EndTime", "Duration",
        # Volume & rates
        "TotalPackets", "TotalBytes", "PacketsPerSec", "BytesPerSec",
        # Directional basics
        "FwdPackets", "BwdPackets", "FwdBytes", "BwdBytes",
        # Pkt length stats (overall + dir)
        "PktLenMin", "PktLenMax", "PktLenMean", "PktLenStd",
        "FwdPktLenMin", "FwdPktLenMax", "FwdPktLenMean", "FwdPktLenStd",
        "BwdPktLenMin", "BwdPktLenMax", "BwdPktLenMean", "BwdPktLenStd",
        # IAT stats (overall + dir)
        "IATCount", "IATMin", "IATMax", "IATMean", "IATStd",
        "FwdIATCount", "FwdIATMin", "FwdIATMax", "FwdIATMean", "FwdIATStd",
        "BwdIATCount", "BwdIATMin", "BwdIATMax", "BwdIATMean", "BwdIATStd",
        # TCP flags
        "TCP_FIN", "TCP_SYN", "TCP_RST", "TCP_PSH", "TCP_ACK", "TCP_URG", "TCP_ECE", "TCP_CWR",
    ]
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for fl in done:
            w.writerow(fl.to_row())

    print(f"✅ Flow timeout used: {flow_timeout} s")
    print(f"✅ TCP fast-close:    {'ON' if fast_close else 'OFF'}")
    print(f"✅ Wrote {len(done)} flows to {csv_path}")
    print(f"✅ Columns: {len(fieldnames)}")


# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="PCAP -> flow CSV with idle timeout (Scapy, advanced features)")
    ap.add_argument("pcap", help="Input PCAP/PCAPNG path")
    ap.add_argument("csv", help="Output CSV path")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="Idle timeout in seconds to split flows (default: 120.0)")
    on = ap.add_argument_group("Fast close (TCP)")
    on.add_argument("--fast-close", dest="fast_close", action="store_true",
                    help="Close TCP flows immediately on FIN/RST (default: ON)")
    on.add_argument("--no-fast-close", dest="fast_close", action="store_false",
                    help="Disable FIN/RST fast-close")
    ap.set_defaults(fast_close=True)
    ap.add_argument("--sweep-every", type=int, default=50000,
                    help="Sweep idle flows every N packets to bound memory (default: 50000)")
    args = ap.parse_args()

    pcap_to_flows(
        pcap_path=args.pcap,
        csv_path=args.csv,
        flow_timeout=args.timeout,
        fast_close=args.fast_close,
        sweep_every=args.sweep_every,
    )


if __name__ == "__main__":
    main()
