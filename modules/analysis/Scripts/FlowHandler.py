from WebData import *
from FlowMemory import *
from Config import *
from TimeUtils import *
from AlertCrafter import *
from dataclasses import field
from datetime import datetime

class FlowProcessor:
    print ("ReceivedFlow")
    flowFlags: list[Flags] = []
    markToCheck = MarkToCheck()
    flowData = FlowData()
    alertCrafter:AlertCrafterLogic
    def __init__(self) -> None:
        self.flowFlags = []
        self.markToCheck = MarkToCheck()
        self.flowData = FlowData()
        pass
    def SetAlertCrafter(self,alertCrafter:AlertCrafterLogic):
        self.alertCrafter = alertCrafter
    def ClassifyFlow(self,flow:WebRecordData):
        currentFlowTime = TimeUtils.parse(flow.start_time)
        for i in range(3):
            if (
                self.flowData.shouldSendPatternAlerts[i]
                and self.flowData.patternWindowEnd[i] != datetime.min
                and TimeUtils.is_older(self.flowData.patternWindowEnd[i], currentFlowTime)
                and hasattr(self, "alertCrafter")
            ):
                self.alertCrafter.simplifiedAlertList[i].cleanup()
        for i in range(0,3):
            self.flowData.flowQueues[i].append(flow) # adding to the window queues
            self.flowData.flowPatternData.AvgPacketAmount[i] += 1
        self.markToCheck = MarkToCheck()
        markToCheck = self.markToCheck
        self.UpdateDetection(flow,1,0) #processing incoming flow
        for i in range(0, 3): #process flow leaving detection window
            windowTime = currentFlowTime
            windowTime = TimeUtils.add(windowTime,0,flow.duration_ms)
            while(True):
                checkedFlow:WebRecordData = self.flowData.flowQueues[i][0]
                flowTime = TimeUtils.parse(checkedFlow.start_time)
                flowTime = TimeUtils.add(flowTime,Config.TimeWindows[i],checkedFlow.duration_ms)
                if(TimeUtils.is_older(flowTime,windowTime)): 
                #if after adding window time to the record it is still older than new records time, it is deleted from window   
                    self.UpdateDetection(checkedFlow,-1,i)
                    self.flowData.flowQueues[i].popleft()
                    self.flowData.flowPatternData.AvgPacketAmount[i]-= 1
                    self.flowData.shouldSendPatternAlerts[i] = True
                    if(i == 2): #check if the biggest window has no data, it means we can remove record to save memory for long term usability
                        if(checkedFlow.src_ip != Config.serviceIp):
                            self.CheckToClearRecord(checkedFlow.src_ip)
                        else:
                            self.CheckToClearRecord(checkedFlow.dst_ip)
                else:
                    break
        
        flowIpProfile: FlowDetectionData 
        if(flow.src_ip != Config.serviceIp):
            flowIpProfile = self.flowData.IPRegistry[flow.src_ip] 
        else:
            flowIpProfile = self.flowData.IPRegistry[flow.dst_ip] 
        

        #detection
        if(markToCheck.PortScan):
            for i in range(0,3):
                if (flowIpProfile.AccesedPortsAmount[i] > Config.PortConnectedTresh[i]):
                    multi = flowIpProfile.AccesedPortsAmount[i]/Config.PortConnectedTresh[i]
                    confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                    AlertCrafterLogic.CraftAlert(self.alertCrafter,"Rule",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.PORT_SCAN,flowIpProfile.AccesedPortsAmount[i])
                if(self.flowData.shouldSendPatternAlerts[i] == True and self.flowData.flowPatternData.PortStats[i].n > Config.MinimumDataForStatistical):
                    score = self.flowData.flowPatternData.PortStats[i].CalcZScore(flowIpProfile.AccesedPortsAmount[i])
                    if(score > 2.5*Config.SeverityMulti[0] * pow(Config.LowDataSampleStatModifier,i)):
                        multi = score - 2.5
                        confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                        AlertCrafterLogic.CraftAlert(self.alertCrafter,"Statistical",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.PORT_SCAN,flowIpProfile.AccesedPortsAmount[i])
        if(markToCheck.DoSslow):
            for i in range(0,3):
                if (flowIpProfile.OpenConnection[i]-flowIpProfile.ClosedConnection[i] > Config.UnclosedConnectionsTresh[i]):
                    multi = (flowIpProfile.OpenConnection[i]-flowIpProfile.ClosedConnection[i])/Config.UnclosedConnectionsTresh[i]
                    confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                    AlertCrafterLogic.CraftAlert(self.alertCrafter,"Rule",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.DoS_Slowloris,flowIpProfile.OpenConnection[i]-flowIpProfile.ClosedConnection[i])
                if(self.flowData.shouldSendPatternAlerts[i] == True and self.flowData.flowPatternData.DoSslow[i].n > Config.MinimumDataForStatistical):
                    score = self.flowData.flowPatternData.DoSslow[i].CalcZScore(flowIpProfile.OpenConnection[i]-flowIpProfile.ClosedConnection[i])
                    if(score > 2.5*Config.SeverityMulti[0] * pow(Config.LowDataSampleStatModifier,i)):
                        multi = score - 2.5
                        confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                        AlertCrafterLogic.CraftAlert(self.alertCrafter,"Statistical",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.DoS_Slowloris,flowIpProfile.OpenConnection[i]-flowIpProfile.ClosedConnection[i])
        if(markToCheck.DoSHulk):
            for i in range(0,3):
                if(flowIpProfile.PSHAmount[i] > Config.PSHRequestsSent[i]):
                    multi = flowIpProfile.PSHAmount[i]/Config.PSHRequestsSent[i]
                    confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                    AlertCrafterLogic.CraftAlert(self.alertCrafter,"Rule",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.DoS_Hulk,flowIpProfile.PSHAmount[i])
                if(self.flowData.shouldSendPatternAlerts[i] == True and self.flowData.flowPatternData.DoSHulk[i].n > Config.MinimumDataForStatistical):
                    score = self.flowData.flowPatternData.DoSHulk[i].CalcZScore(flowIpProfile.PSHAmount[i])
                    if(score > 2.5*Config.SeverityMulti[0] * pow(Config.LowDataSampleStatModifier,i)):
                        multi = score - 2.5
                        confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                        AlertCrafterLogic.CraftAlert(self.alertCrafter,"Statistical",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.DoS_Hulk,flowIpProfile.PSHAmount[i])
        if(markToCheck.Brute):
            for i in range(0,3):
                if(flowIpProfile.ClosedConnection[i] > Config.BruteConnectionsTresh[i]):
                    multi = flowIpProfile.ClosedConnection[i]/Config.BruteConnectionsTresh[i]
                    confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                    AlertCrafterLogic.CraftAlert(self.alertCrafter,"Rule",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.BRUTE_FORCE_LIKE,flowIpProfile.ClosedConnection[i])
                if(self.flowData.shouldSendPatternAlerts[i] == True and self.flowData.flowPatternData.Brute[i].n > Config.MinimumDataForStatistical):
                    score = self.flowData.flowPatternData.Brute[i].CalcZScore(flowIpProfile.ClosedConnection[i])
                    if(score > 2.5*Config.SeverityMulti[0] * pow(Config.LowDataSampleStatModifier,i)):
                        multi = score - 2.5
                        confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                        AlertCrafterLogic.CraftAlert(self.alertCrafter,"Statistical",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.BRUTE_FORCE_LIKE,flowIpProfile.ClosedConnection[i])
        for i in range(0,3):
            if(self.flowData.shouldSendPatternAlerts[i] == True):
                if(self.flowData.flowPatternData.AvgPacketAmount[i] > Config.AvgFlowPerS[i]):
                    multi = self.flowData.flowPatternData.AvgPacketAmount[i]/Config.AvgFlowPerS[i]
                    confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                    AlertCrafterLogic.CraftAlert(self.alertCrafter,"Rule",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.Abnormal_Connection_Heavy_Traffic,self.flowData.flowPatternData.AvgPacketAmount[i])
                if(self.flowData.flowPatternData.TotalPacketSize[i] > Config.AvgPacketSize[i] and self.flowData.flowPatternData.AvgPacketAmount[i] > Config.MinimumDataForStatistical):
                    multi = self.flowData.flowPatternData.TotalPacketSize[i]/Config.AvgPacketSize[i]
                    confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                    AlertCrafterLogic.CraftAlert(self.alertCrafter,"Rule",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.Abnormal_Connection_Big_Payloads,self.flowData.flowPatternData.TotalPacketSize[i])
        #Update pattern Window
        for i in range(0,3):
            if(self.flowData.shouldSendPatternAlerts[i] == True):
                if(self.flowData.patternWindowEnd[i] == datetime.min):
                    self.flowData.patternWindowEnd[i] = TimeUtils.add(currentFlowTime,Config.TimeWindows[i])
                elif(TimeUtils.is_older(self.flowData.patternWindowEnd[i],currentFlowTime)):
                    self.flowData.patternWindowEnd[i] = TimeUtils.add(currentFlowTime,Config.TimeWindows[i])
                    if(self.flowData.flowPatternData.AvgPacketAmount[i] > Config.MinimumDataForStatistical):
                        score = self.flowData.flowPatternData.AvgPacketAmountStats[i].CalcZScore(self.flowData.flowPatternData.AvgPacketAmount[i])
                        if(score > 2.5*Config.SeverityMulti[0]):
                            multi = score - 2.5
                            confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                            AlertCrafterLogic.CraftAlert(self.alertCrafter,"Statistical",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.Abnormal_Connection_Heavy_Traffic,self.flowData.flowPatternData.AvgPacketAmount[i])
                    self.flowData.flowPatternData.AvgPacketAmountStats[i].Add(self.flowData.flowPatternData.AvgPacketAmount[i])
                    if(self.flowData.flowPatternData.AvgPacketAmount[i] > Config.MaximumDataForStatistical):
                        self.flowData.flowPatternData.AvgPacketAmountStats[i].Low()
                    if(self.flowData.flowPatternData.TotalPacketSize[i] > Config.MinimumDataForStatistical):
                        score = self.flowData.flowPatternData.TotalPacketSizeStats[i].CalcZScore(self.flowData.flowPatternData.TotalPacketSize[i])
                        if(score > 2.5*Config.SeverityMulti[0]):
                            multi = score - 2.5
                            confidence = self.normalize(multi,Config.SeverityMulti[0], Config.SeverityMulti[2])
                            AlertCrafterLogic.CraftAlert(self.alertCrafter,"Statistical",self.JudgeSeverity(multi),confidence,flow,i,AlertTypes.Abnormal_Connection_Big_Payloads,self.flowData.flowPatternData.TotalPacketSize[i])
                    self.flowData.flowPatternData.TotalPacketSizeStats[i].Add(self.flowData.flowPatternData.TotalPacketSize[i])
                    if(self.flowData.flowPatternData.TotalPacketSize[i] > Config.MaximumDataForStatistical):
                        self.flowData.flowPatternData.TotalPacketSizeStats[i].Low()

        return

    def UpdateDetection(self, flow:WebRecordData,incoming:int,window:int): # incoming 1 or -1, window 0-2 when incoming -1
        b:int
        e:int
        if(incoming == 1):
            b = 0
            e = 3
        else:
            b = window
            e = window + 1
        for i in range(b,e):
            self.flowData.flowPatternData.TotalPacketSize[i] += flow.bytes * incoming
        self.flowFlags = []
        if(flow.protocol == "TCP" and flow.tcp_flags is not None):
            self.FlagExtractor(flow.tcp_flags)
        if(flow.src_ip != Config.serviceIp): #check if the packet is from service or client - here client
            if( flow.src_ip in self.flowData.IPRegistry.keys() ) == False:
                flowDetectionData = FlowDetectionData()
                self.flowData.IPRegistry[flow.src_ip] = flowDetectionData
            else:
                flowDetectionData = self.flowData.IPRegistry[flow.src_ip]
            if(flow.protocol == "TCP"):
                if Flags.SYN in self.flowFlags or Flags.FIN in self.flowFlags or len(self.flowFlags) == 0:
                    self.ModifyAccesedPorts(flow,flowDetectionData,window,incoming)
            if(flow.protocol == "UDP"):
                    self.ModifyAccesedPorts(flow,flowDetectionData,window,incoming)
            if(flow.protocol == "TCP"):
                    if Flags.SYN in self.flowFlags: #check if connection was open
                        for i in range(b,e):
                            connnectionsAmount = flowDetectionData.OpenConnection[i] - flowDetectionData.ClosedConnection[i]
                            if(incoming == 1 and connnectionsAmount >= 0):
                                self.flowData.flowPatternData.DoSslow[i].Add(connnectionsAmount)
                            elif(connnectionsAmount > 0):
                                self.flowData.flowPatternData.DoSslow[i].Low(connnectionsAmount)        
                            flowDetectionData.OpenConnection[i] += incoming                    
                        self.markToCheck.DoSslow = True
                    if Flags.PSH in self.flowFlags:
                        for i in range(b,e):
                            flowDetectionData.PSHAmount[i] += incoming
                            if(incoming == 1):
                                self.flowData.flowPatternData.DoSHulk[i].Add(flowDetectionData.PSHAmount[i] - 1)
                            else:
                                self.flowData.flowPatternData.DoSHulk[i].Low(flowDetectionData.PSHAmount[i] + 1)
                        self.markToCheck.DoSHulk = True
        else:  #packet is from service
            if( flow.dst_ip in self.flowData.IPRegistry.keys() ) == False:
                flowDetectionData = FlowDetectionData()
                self.flowData.IPRegistry[flow.dst_ip] = flowDetectionData
            else:
                flowDetectionData = self.flowData.IPRegistry[flow.dst_ip]
            if(flow.protocol == "TCP"):
                if Flags.FIN in self.flowFlags or Flags.RST in self.flowFlags: # check if connection was terminated by server
                    for i in range(b,e):
                        flowDetectionData.ClosedConnection[i] += incoming
                        if(incoming == 1):
                            if(flowDetectionData.ClosedConnection[i] <= flowDetectionData.OpenConnection[i]):
                                self.flowData.flowPatternData.DoSslow[i].Low(flowDetectionData.OpenConnection[i] - flowDetectionData.ClosedConnection[i] + 1)
                            self.flowData.flowPatternData.Brute[i].Add(flowDetectionData.ClosedConnection[i] - 1)
                        else:
                            if(flowDetectionData.ClosedConnection[i] < flowDetectionData.OpenConnection[i]):
                                self.flowData.flowPatternData.DoSslow[i].Add(flowDetectionData.OpenConnection[i] - flowDetectionData.ClosedConnection[i] - 1)
                            self.flowData.flowPatternData.Brute[i].Low(flowDetectionData.ClosedConnection[i] + 1)
                    self.markToCheck.Brute = True
        return

    def FlagExtractor(self,flagInt:int):
        flags = flagInt or 0  # null for non-TCP flows (FlowEvent v1)
        div = 256
        while(flags > 0):
            if(flags>=div):
                self.flowFlags.append(Flags(div))
                flags-=div
            div = div/2

    def ModifyAccesedPorts(self,flow:WebRecordData,flowDetectionData:FlowDetectionData,table:int,incoming:int):
        #adds accesed ports to memory
        self.markToCheck.PortScan = True
        if(incoming == 1):
            for i in range(0,3):
                    ports = flowDetectionData.PortList[i]
                    ports.add(flow.dst_port)
                    portCount = len(set(ports))
                    if(portCount > flowDetectionData.AccesedPortsAmount[i]):
                        self.flowData.flowPatternData.PortStats[i].Add(flowDetectionData.AccesedPortsAmount[i])
                        flowDetectionData.AccesedPortsAmount[i] = portCount
        else:
            ports = flowDetectionData.PortList[table]
            ports.remove(flow.dst_port,1)
            portCount = len(set(ports))
            if(portCount < flowDetectionData.AccesedPortsAmount[table]):
                self.flowData.flowPatternData.PortStats[table].Low(flowDetectionData.AccesedPortsAmount[table])
                flowDetectionData.AccesedPortsAmount[table] = portCount
        
    def CheckToClearRecord(self,ipAdress:str):
        detectionData:FlowDetectionData = self.flowData.IPRegistry[ipAdress]
        #if every data entry is empty, we can get rid of the record
        if (detectionData.AccesedPortsAmount[2] <= 0):
            if(detectionData.OpenConnection[2]<=0):
                if(detectionData.ClosedConnection[2]<=0):
                    if(detectionData.PSHAmount[2]<=0):
                        del(detectionData)
                        self.flowData.IPRegistry.pop(ipAdress)
    def JudgeSeverity(self,multi:float) -> str:
        #Used once, but could be transscribed to an enum
        if(multi>Config.SeverityMulti[2]):
            return "Severe"
        if(multi>Config.SeverityMulti[1]):
            return "Medium"
        else:
            return "Minor"
    def normalize(self,x: float, a: float, b: float) -> float:
        if a == b:
            raise ValueError("Range cannot be zero")
        return max(0.0, min(1.0, (x - a) / (b - a)))

        
            
    