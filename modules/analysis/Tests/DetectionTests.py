from pathlib import Path
from unittest import TestCase, main
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Scripts"))
from FlowHandler import FlowProcessor
from WebData import WebRecordData
from Config import Config
class TestBasicTests(TestCase):
    flowHandler:FlowProcessor = FlowProcessor()
    clientIP = "192.0.2.10"
    webDataSyn: WebRecordData = WebRecordData(
        start_time="2025-01-15T12:34:56.789Z",
        duration_ms=1250.5,
        src_ip=clientIP,
        src_port=54321,
        dst_ip=Config.serviceIp,
        dst_port=443,
        protocol="TCP",
        packets=12,
        bytes=2048,
        tcp_flags=2,
    )
    webDataUDP: WebRecordData = WebRecordData(
            start_time="2025-01-15T12:34:56.789Z",
            duration_ms=1250.5,
            src_ip=clientIP,
            src_port=54321,
            dst_ip=Config.serviceIp,
            dst_port=443,
            protocol="UDP",
            packets=12,
            bytes=2048,
            tcp_flags=2,
        )
    webDataNull: WebRecordData = WebRecordData(
                start_time="2025-01-15T12:34:56.789Z",
                duration_ms=1250.5,
                src_ip=clientIP,
                src_port=54321,
                dst_ip=Config.serviceIp,
                dst_port=400,
                protocol="TCP",
                packets=12,
                bytes=2048,
                tcp_flags=None,
            )
    webDataFinClient: WebRecordData = WebRecordData(
                    start_time="2025-01-15T12:34:56.789Z",
                    duration_ms=1250.5,
                    src_ip=clientIP,
                    src_port=54321,
                    dst_ip=Config.serviceIp,
                    dst_port=400,
                    protocol="TCP",
                    packets=12,
                    bytes=2048,
                    tcp_flags=1,
                )
    webDataFinService: WebRecordData = WebRecordData(
                        start_time="2025-01-15T12:34:56.789Z",
                        duration_ms=1250.5,
                        src_ip=Config.serviceIp,
                        src_port=54321,
                        dst_ip=clientIP,
                        dst_port=400,
                        protocol="TCP",
                        packets=12,
                        bytes=2048,
                        tcp_flags=1,
                    )
    webDataPsh: WebRecordData = WebRecordData(
                        start_time="2025-01-15T12:34:56.789Z",
                        duration_ms=1250.5,
                        src_ip=clientIP,
                        src_port=54321,
                        dst_ip=Config.serviceIp,
                        dst_port=400,
                        protocol="TCP",
                        packets=12,
                        bytes=2048,
                        tcp_flags=8,
                    )
    webData1s: WebRecordData = WebRecordData(
                        start_time="2025-01-15T12:34:58.789Z",
                        duration_ms=1250.5,
                        src_ip=clientIP,
                        src_port=54321,
                        dst_ip=Config.serviceIp,
                        dst_port=400,
                        protocol="TCP",
                        packets=12,
                        bytes=2048,
                        tcp_flags=8,
                    )
    webData60s: WebRecordData = WebRecordData(
                            start_time="2025-01-15T12:36:00.789Z",
                            duration_ms=1250.5,
                            src_ip=clientIP,
                            src_port=54321,
                            dst_ip=Config.serviceIp,
                            dst_port=400,
                            protocol="TCP",
                            packets=12,
                            bytes=2048,
                            tcp_flags=8,
                        )
    webData10s: WebRecordData = WebRecordData(
                            start_time="2025-01-15T12:35:20.789Z",
                            duration_ms=1250.5,
                            src_ip=clientIP,
                            src_port=54321,
                            dst_ip=Config.serviceIp,
                            dst_port=400,
                            protocol="TCP",
                            packets=12,
                            bytes=2048,
                            tcp_flags=8,
                        )
    def test_detection(self):
        self.flowHandler.ClassifyFlow(self.webDataSyn)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].OpenConnection[0],1)
        self.flowHandler.ClassifyFlow(self.webDataUDP)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[0][443],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[0],1)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[1],1)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[2],1)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].OpenConnection[0],1)
        self.flowHandler.ClassifyFlow(self.webDataNull)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[0][443],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[0][400],1)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[0],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[1],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[2],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].OpenConnection[0],1)
        self.flowHandler.ClassifyFlow(self.webDataFinClient)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[0][443],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[0][400],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[0],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[1],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[2],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].OpenConnection[0],1)
        self.flowHandler.ClassifyFlow(self.webDataFinService)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].OpenConnection[0],1)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].ClosedConnection[0],1)
        self.flowHandler.ClassifyFlow(self.webDataPsh)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PSHAmount[0],1)
        self.assertEqual(self.flowHandler.flowData.flowPatternData.AvgPacketAmount[0],6)
        self.assertEqual(self.flowHandler.flowData.flowPatternData.TotalPacketSize[0],6*2048)
        self.flowHandler.ClassifyFlow(self.webData1s)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[0][443],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[0][400],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[0],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[1],2)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[2],2)
        self.flowHandler.ClassifyFlow(self.webData10s)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[1][443],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[1][400],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[0],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[1],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[2],2)
        self.flowHandler.ClassifyFlow(self.webData60s)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[2][443],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].PortList[2][400],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[0],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[1],0)
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].AccesedPortsAmount[2],0)





if __name__ == '__main__':
    main()