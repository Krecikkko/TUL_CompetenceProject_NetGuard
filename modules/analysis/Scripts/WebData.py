from dataclasses import dataclass
from typing import Optional


@dataclass
class WebRecordData:
    """One FlowEvent v1 message (contracts/kafka/flow-event.v1.schema.json).

    Field names and types follow the contract exactly, because Decoder builds
    this object with WebRecordData(**message).
    """
    start_time: str = ""
    duration_ms: float = 0.0
    src_ip: str = ""
    src_port: Optional[int] = None      # null for ICMP / ICMPV6 / OTHER
    dst_ip: str = ""
    dst_port: Optional[int] = None      # null for ICMP / ICMPV6 / OTHER
    protocol: str = ""                # "TCP" | "UDP" | "ICMP" | "ICMPV6" | "OTHER"
    packets: int = 0
    bytes: int = 0
    tcp_flags: Optional[int] = None     # null for non-TCP flows
