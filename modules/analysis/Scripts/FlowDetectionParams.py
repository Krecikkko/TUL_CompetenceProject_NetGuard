from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
import numpy as np
from multiset import Multiset
from StatisticsList import ZScore

@dataclass
class FlowDetectionData:
    PortList: list[Multiset] = field(default_factory=lambda: [Multiset() for _ in range(3)])
    AccesedPortsAmount: list[int] = field(default_factory=lambda: [0,0,0])
    OpenConnection: list[int] = field(default_factory=lambda: [0,0,0])
    ClosedConnection: list[int] = field(default_factory=lambda: [0,0,0])
    PSHAmount: list[int] = field(default_factory=lambda: [0,0,0])

@dataclass
class FlowPatternData:
    TotalPacketSize: list[int] = field(default_factory=lambda: [0,0,0])
    AvgPacketAmount: list[int] = field(default_factory=lambda: [0,0,0])
    PortStats: list[ZScore] = field(default_factory=lambda: [ZScore() for _ in range(3)])
    DoSslow: list[ZScore] = field(default_factory=lambda: [ZScore() for _ in range(3)])
    DoSHulk: list[ZScore] = field(default_factory=lambda: [ZScore() for _ in range(3)])
    Brute: list[ZScore] = field(default_factory=lambda: [ZScore() for _ in range(3)])

@dataclass
class MarkToCheck:
    PortScan:bool = False
    DoSslow:bool = False
    DoSHulk:bool = False
    Brute:bool = False

class Flags(Enum):
    FIN = 1
    SYN = 2
    RST = 4
    PSH = 8
    ACK = 16
    URG = 32
    ECE = 64
    CWR = 128
    NS = 256