from pathlib import Path
from unittest import TestCase, main
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Scripts"))
from FlowHandler import FlowProcessor
from WebData import WebRecordData
from Config import Config
from FlowDetectionParams import FlowDetectionData
class TestBasicTests(TestCase):
    flowHandler:FlowProcessor = FlowProcessor()
    webData: WebRecordData = WebRecordData(
        start_time="2025-01-15T12:34:56.789Z",
        duration_ms=1250.5,
        src_ip="192.0.2.10",
        src_port=54321,
        dst_ip=Config.serviceIp,
        dst_port=443,
        protocol="TCP",
        packets=12,
        bytes=2048,
        tcp_flags=2,
    )
    def test_basic(self):
        self.flowHandler.ClassifyFlow(self.webData)
        self.assertEqual(self.webData.protocol, "TCP")
        self.assertEqual(self.flowHandler.flowData.flowPatternData.TotalPacketSize[0], 2048)
        self.assertIsNotNone(self.flowHandler.flowData.IPRegistry["192.0.2.10"])
        self.assertEqual(self.flowHandler.flowData.IPRegistry["192.0.2.10"].OpenConnection[0],1)

    def test_flow_state_is_isolated(self):
        first = FlowProcessor()
        second = FlowProcessor()
        first.flowData.flowQueues[0].append(self.webData)
        first.flowData.flowPatternData.TotalPacketSize[0] = 2048
        first.flowData.flowPatternData.PortStats[0].Add(0)
        profile = FlowDetectionData()
        profile.PortList[0].add(443)
        first.flowData.IPRegistry["192.0.2.10"] = profile

        self.assertEqual(len(second.flowData.flowQueues[0]), 0)
        self.assertEqual(second.flowData.flowPatternData.TotalPacketSize[0], 0)
        self.assertEqual(second.flowData.flowPatternData.PortStats[0].counts, {})
        self.assertEqual(second.flowData.IPRegistry, {})
        self.assertEqual(FlowDetectionData().PortList[0][443], 0)

if __name__ == '__main__':
    main()
    

