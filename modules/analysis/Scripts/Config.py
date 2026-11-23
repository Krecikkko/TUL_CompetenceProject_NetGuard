import numpy as np


class Config:
    TimeWindows = [1,10,60]
    PortConnectedTresh = [10,20,50]
    UnclosedConnectionsTresh = [100,200,300]
    PSHRequestsSent = [300,1000,5000]
    BruteConnectionsTresh = [5,20,60]
    AvgPacketSize = [100000000,1000000000,1000000000]
    AvgFlowPerS = [2500,20000,100000]
    SeverityMulti = [1,1.5,2]
    MinimumDataForStatistical = 10
    MaximumDataForStatistical = 2000
    LowDataSampleStatModifier = 1.2
    serviceIp = '127.1.1.1'