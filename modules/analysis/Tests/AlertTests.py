from collections import Counter
from math import sqrt
from pathlib import Path
from unittest import TestCase, main
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Scripts"))

from AlertCrafter import AlertCrafterLogic
from AlertParams import AlertTypes
from Config import Config
from FlowDetectionParams import FlowDetectionData
from FlowHandler import FlowProcessor
from TimeUtils import TimeUtils
from WebData import WebRecordData


class TestAlertGeneration(TestCase):
    client_ip = "192.0.2.10"

    def setUp(self):
        config_fields = (
            "TimeWindows",
            "PortConnectedTresh",
            "UnclosedConnectionsTresh",
            "PSHRequestsSent",
            "BruteConnectionsTresh",
            "AvgPacketSize",
            "AvgFlowPerS",
            "SeverityMulti",
        )
        self.original_config = {name: getattr(Config, name) for name in config_fields}
        self.addCleanup(self._restore_config)

        Config.TimeWindows = [1, 2, 3]
        Config.PortConnectedTresh = [1000] * 3
        Config.UnclosedConnectionsTresh = [1000] * 3
        Config.PSHRequestsSent = [1000] * 3
        Config.BruteConnectionsTresh = [1000] * 3
        Config.AvgPacketSize = [10000] * 3
        Config.AvgFlowPerS = [1000] * 3
        Config.SeverityMulti = [1, 1.5, 2]
        self._new_harness()

    def _restore_config(self):
        for name, value in self.original_config.items():
            setattr(Config, name, value)

    def _new_harness(self):
        self.flow_processor = FlowProcessor()
        self.alert_crafter = AlertCrafterLogic()
        self.alert_crafter.alertQueue = []
        self.flow_processor.SetAlertCrafter(self.alert_crafter)

    def _flow(self, protocol="TCP", tcp_flags: int | None = 16, byte_count=100,
              src_ip=None, dst_port=443):
        if src_ip is None:
            src_ip = self.client_ip
        dst_ip = Config.serviceIp if src_ip != Config.serviceIp else self.client_ip
        return WebRecordData(
            start_time="2025-01-15T12:34:56.789Z",
            duration_ms=0,
            src_ip=src_ip,
            src_port=54321,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            packets=1,
            bytes=byte_count,
            tcp_flags=tcp_flags,
        )

    def _assert_alert(self, alert, flow, window, method, rule_id, alert_type,
                      feature_name, feature_value, severity, confidence):
        self.assertEqual(alert.method, method)
        self.assertEqual(alert.rule_id, rule_id)
        self.assertEqual(alert.type, alert_type)
        self.assertEqual(alert.severity, severity)
        self.assertAlmostEqual(alert.confidence, confidence)
        self.assertEqual(alert.src_ip, flow.src_ip)
        self.assertEqual(alert.dst_ip, flow.dst_ip)
        self.assertEqual(alert.duration_seconds, window)
        expected_start = TimeUtils.add(TimeUtils.parse(flow.start_time), -window, 0)
        self.assertEqual(alert.window_start, str(expected_start))
        self.assertTrue(alert.timestamp)
        self.assertEqual(len(alert.features), 1)
        self.assertEqual(alert.features[0].name, feature_name)
        self.assertEqual(alert.features[0].value, feature_value)
        self.assertTrue(alert.explanation)

    def _assert_rule_alerts(self, flow, rule_id, alert_type, feature_name, feature_value):
        alerts = self.alert_crafter.alertQueue
        self.assertEqual(len(alerts), len(Config.TimeWindows))
        for alert, window in zip(alerts, Config.TimeWindows):
            with self.subTest(window=window):
                self._assert_alert(
                    alert, flow, window, "Rule", rule_id, alert_type,
                    feature_name, feature_value, "Medium", 1.0,
                )

    def _assert_statistical_alert(self, flow, window, rule_id, alert_type,
                                  feature_name, feature_value, baseline):
        alerts = self.alert_crafter.alertQueue
        self.assertEqual(len(alerts), 1)
        mean = sum(baseline) / len(baseline)
        variance = sum((value - mean) ** 2 for value in baseline) / (len(baseline) - 1)
        score = (feature_value - mean) / sqrt(variance)
        multi = score - 3
        if multi > Config.SeverityMulti[2]:
            severity = "Severe"
        elif multi > Config.SeverityMulti[1]:
            severity = "Medium"
        else:
            severity = "Minor"
        confidence = max(
            0.0,
            min(1.0, (multi - Config.SeverityMulti[0]) /
                (Config.SeverityMulti[2] - Config.SeverityMulti[0])),
        )
        self._assert_alert(
            alerts[0], flow, window, "Statistical", rule_id, alert_type,
            feature_name, feature_value, severity, confidence,
        )

    def _seed_zscore(self, zscore, values):
        zscore.counts = Counter(values)
        zscore.n = len(values)
        zscore.total_sum = sum(values)
        zscore.sum_sq = sum(value * value for value in values)

    def test_rule_port_scan_each_window(self):
        Config.PortConnectedTresh = [1] * 3
        flow = self._flow(tcp_flags=2)

        self.flow_processor.ClassifyFlow(flow)
        flow = self._flow(tcp_flags=2,dst_port=102)
        self.flow_processor.ClassifyFlow(flow)

        self._assert_rule_alerts(
            flow, "Port_Scan", "Port_Scan", "Ports Scanned", 2,
        )

    def test_rule_slowloris_each_window(self):
        Config.UnclosedConnectionsTresh = [1] * 3
        flow = self._flow(tcp_flags=2)

        self.flow_processor.ClassifyFlow(flow)
        self.flow_processor.ClassifyFlow(flow)

        self._assert_rule_alerts(
            flow, "DoS_Slowloris", "DoS", "Maintained open connections", 2,
        )

    def test_rule_hulk_each_window(self):
        Config.PSHRequestsSent = [1] * 3
        flow = self._flow(tcp_flags=8)

        self.flow_processor.ClassifyFlow(flow)
        self.flow_processor.ClassifyFlow(flow)
        self._assert_rule_alerts(
            flow, "DoS_Hulk", "DoS", "PSH requests amount", 2,
        )

    def test_rule_brute_force_each_window(self):
        Config.BruteConnectionsTresh = [1,1,1]
        #profile = FlowDetectionData()
        #self.flow_processor.flowData.IPRegistry[self.client_ip] = profile
        flow = self._flow(tcp_flags=1, src_ip=Config.serviceIp)

        self.flow_processor.ClassifyFlow(flow)
        self.flow_processor.ClassifyFlow(flow)

        self._assert_rule_alerts(
            flow, "Brute_Force", "Brute_Force", "Failed connections amount", 2,
        )

    def test_rule_heavy_traffic_each_window(self):
        Config.AvgFlowPerS = [1] * 3
        self.flow_processor.flowData.shouldSendPatternAlerts = [True] * 3
        flow = self._flow()

        self.flow_processor.ClassifyFlow(flow)
        self.flow_processor.ClassifyFlow(flow)

        self._assert_rule_alerts(
            flow, "Abnormal_Connection_Heavy_Traffic", "Abnormal_Connection",
            "Average traffic amount", 2,
        )

    def test_rule_big_payloads_each_window(self):
        Config.AvgPacketSize = [50] * 3
        self.flow_processor.flowData.shouldSendPatternAlerts = [True] * 3
        flow = self._flow(byte_count=100)

        self.flow_processor.ClassifyFlow(flow)

        self._assert_rule_alerts(
            flow, "Abnormal_Connection_Big_Payloads", "Abnormal_Connection",
            "Average payload size", 100,
        )

    def test_zscore_port_scan_each_window(self):
        Config.PortConnectedTresh = [1000] * 3

        for window_index, window in enumerate(Config.TimeWindows):
            with self.subTest(window=window):
                self._new_harness()
                profile = FlowDetectionData()
                for index in range(3):
                    for port in range(2000, 2020):
                        profile.PortList[index].add(port)
                    profile.AccesedPortsAmount[index] = 20
                    self._seed_zscore(
                        self.flow_processor.flowData.flowPatternData.PortStats[index],
                        [1] * 20 + [10],
                    )
                self.flow_processor.flowData.IPRegistry[self.client_ip] = profile
                self.flow_processor.flowData.shouldSendPatternAlerts[window_index] = True
                flow = self._flow(protocol="UDP", tcp_flags=None, dst_port=2000)

                self.flow_processor.ClassifyFlow(flow)

                self._assert_statistical_alert(
                    flow, window, "Port_Scan", "Port_Scan", "Ports Scanned", 20,
                    [1] * 20 + [10],
                )

    def test_zscore_slowloris_each_window(self):
        Config.UnclosedConnectionsTresh = [1000] * 3

        for window_index, window in enumerate(Config.TimeWindows):
            with self.subTest(window=window):
                self._new_harness()
                profile = FlowDetectionData()
                for index in range(3):
                    profile.OpenConnection[index] = 5
                    self._seed_zscore(
                        self.flow_processor.flowData.flowPatternData.DoSslow[index],
                        [1] * 20 + [5],
                    )
                    self._seed_zscore(
                        self.flow_processor.flowData.flowPatternData.PortStats[index],
                        [1, 2, 3],
                    )
                self.flow_processor.flowData.IPRegistry[self.client_ip] = profile
                self.flow_processor.flowData.shouldSendPatternAlerts[window_index] = True
                flow = self._flow(tcp_flags=2)

                self.flow_processor.ClassifyFlow(flow)

                self._assert_statistical_alert(
                    flow, window, "DoS_Slowloris", "DoS", "Maintained open connections", 6,
                    [1] * 20 + [6],
                )

    def test_zscore_hulk_each_window(self):
        Config.PSHRequestsSent = [1000] * 3

        for window_index, window in enumerate(Config.TimeWindows):
            with self.subTest(window=window):
                self._new_harness()
                profile = FlowDetectionData()
                for index in range(3):
                    profile.PSHAmount[index] = 10
                    self._seed_zscore(
                        self.flow_processor.flowData.flowPatternData.DoSHulk[index],
                        [1] * 20 + [10],
                    )
                self.flow_processor.flowData.IPRegistry[self.client_ip] = profile
                self.flow_processor.flowData.shouldSendPatternAlerts[window_index] = True
                flow = self._flow(tcp_flags=8)

                self.flow_processor.ClassifyFlow(flow)

                self._assert_statistical_alert(
                    flow, window, "DoS_Hulk", "DoS", "PSH requests amount", 11,
                    [1] * 20 + [11],
                )

    def test_zscore_brute_force_each_window(self):
        Config.BruteConnectionsTresh = [1000] * 3

        for window_index, window in enumerate(Config.TimeWindows):
            with self.subTest(window=window):
                self._new_harness()
                profile = FlowDetectionData()
                for index in range(3):
                    profile.ClosedConnection[index] = 10
                    self._seed_zscore(
                        self.flow_processor.flowData.flowPatternData.Brute[index],
                        [1] * 20 + [10],
                    )
                self.flow_processor.flowData.IPRegistry[self.client_ip] = profile
                self.flow_processor.flowData.shouldSendPatternAlerts[window_index] = True
                flow = self._flow(tcp_flags=1, src_ip=Config.serviceIp)

                self.flow_processor.ClassifyFlow(flow)

                self._assert_statistical_alert(
                    flow, window, "Brute_Force", "Brute_Force",
                    "Failed connections amount", 11, [1] * 20 + [11],
                )
if __name__ == '__main__':
    main()
    