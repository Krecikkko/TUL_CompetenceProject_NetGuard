import WebData
from collections import deque
from dataclasses import dataclass, field
from FlowDetectionParams import *
from enum import Enum
from datetime import datetime

@dataclass
class FlowData:
    flowQueues: list[deque] = field(default_factory=lambda: [deque() for _ in range(3)])
    IPRegistry: dict[str, FlowDetectionData] = field(default_factory=dict)
    flowPatternData: FlowPatternData = field(default_factory=FlowPatternData)
    shouldSendPatternAlerts: list[bool] = field(default_factory=lambda: [False,False,False])
    patternWindowEnd:list[datetime] = field(default_factory=lambda: [datetime.min,datetime.min,datetime.min])
    


