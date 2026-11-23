from AlertData import *
from enum import Enum
from WebData import *
from AlertParams import *
from Config import *
from time import time
from TimeUtils import TimeUtils
from kafkaProducer import AlertProducer

class SimplifiedAlertManager:
    def __init__(self):
        self.resources:set[tuple[str,str,str,AlertTypes]] = set()

    def add(self, srcIp: str,method:str, severity: str, alertType: AlertTypes) -> bool:
        key = (srcIp,method,severity,alertType)
        if(key in self.resources):
               return True
        self.resources.add(key)
        return False

    def cleanup(self):
        self.resources.clear()

class AlertCrafterLogic:
    producer:AlertProducer
    simplifiedAlertList:List[SimplifiedAlertManager]
    alertQueue: list[AlertData]

    def __init__(self):
        self.simplifiedAlertList = [SimplifiedAlertManager() for _ in Config.TimeWindows]
        self.alertQueue = []

    def CraftAlert(self,method:str,severity:str,confidence:float,flow:WebRecordData,windowType:int,alertType:AlertTypes,featureParam:int | str | float):
        if(alertType.name != AlertTypes.BRUTE_FORCE_LIKE):
               if(self.simplifiedAlertList[windowType].add(flow.src_ip,method,severity,alertType)):
                      return
        else:
               if(self.simplifiedAlertList[windowType].add(flow.dst_ip,method,severity,alertType)):
                    return
        alertData:AlertData = AlertData()
        alertData.type = AlertTypes(alertType.value - alertType.value%10).name
        alertData.method = method
        alertData.rule_id = alertType.name
        alertData.severity = severity
        alertData.confidence = confidence
        alertData.src_ip = flow.src_ip
        alertData.dst_ip = flow.dst_ip
        alertData.timestamp = str(time())
        alertData.window_start = str(TimeUtils.add(TimeUtils.parse(flow.start_time),-Config.TimeWindows[windowType],0))
        alertData.duration_seconds = Config.TimeWindows[windowType]
        if(alertType == AlertTypes.PORT_SCAN):
            alertData.features.append(DetectionFeature("Ports Scanned", featureParam))
            alertData.explanation = "Multiple ports were checked by a single user, potentially in an attempt to find vurnabilities"
        if(alertType == AlertTypes.DoS_Slowloris):
                    alertData.features.append(DetectionFeature("Maintained open connections", featureParam))
                    alertData.explanation = "Single user maintained multiple open connections potentially denying service"
        if(alertType == AlertTypes.DoS_Hulk):
                    alertData.features.append(DetectionFeature("PSH requests amount", featureParam))
                    alertData.explanation = "Single user send too many requests potentially overloading server"
        if(alertType == AlertTypes.BRUTE_FORCE_LIKE):
                    alertData.features.append(DetectionFeature("Failed connections amount", featureParam))
                    alertData.explanation = "Single user failed to connect or was denied multiple times, suggesting attack on access credentials"
        if(alertType == AlertTypes.Abnormal_Connection_Big_Payloads):
                    alertData.features.append(DetectionFeature("Average payload size", featureParam))
                    alertData.explanation = "Observed increase in size of packets during window, unrelated to the packet"
        if(alertType == AlertTypes.Abnormal_Connection_Heavy_Traffic):
                    alertData.features.append(DetectionFeature("Average traffic amount", featureParam))
                    alertData.explanation = "Observed above average traffic amount, unrelated to the packet"
        self.alertQueue.append(alertData)        
        return
        