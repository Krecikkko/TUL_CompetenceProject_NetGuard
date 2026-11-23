from enum import Enum

class AlertTypes(Enum):
    PORT_SCAN = 10
    DOS_LIKE = 20
    DoS_Hulk = 21
    DoS_Slowloris = 22
    BRUTE_FORCE_LIKE = 30
    ABNORMAL_CONNECTION_PATTERN = 40
    Abnormal_Connection_Big_Payloads = 41
    Abnormal_Connection_Heavy_Traffic = 42