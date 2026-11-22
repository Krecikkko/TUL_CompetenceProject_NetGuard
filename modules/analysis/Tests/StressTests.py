from contextlib import redirect_stdout
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
import random
from time import perf_counter
from unittest import TestCase, main

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Scripts"))

from AlertCrafter import AlertCrafterLogic
from Config import Config
from FlowHandler import FlowProcessor
from WebData import WebRecordData


class TestFlowStress(TestCase):
    flow_count = 5000

    def generate_flows(self):
        rng = random.Random(42)
        start = datetime(2025, 1, 15, tzinfo=timezone.utc)
        service_ports = (22, 53, 80, 123, 443, 8080, 8443)
        tcp_flags = (1, 2, 4, 8, 16, 17, 18)
        flows = []

        for index in range(self.flow_count):
            client_ip = f"192.0.2.{rng.randint(1, 254)}"
            from_service = rng.choice((True, False))
            protocol = rng.choice(("TCP", "UDP"))
            service_port = rng.choice(service_ports)
            client_port = rng.randint(1024, 65535)

            if from_service:
                src_ip, dst_ip = Config.serviceIp, client_ip
                src_port, dst_port = service_port, client_port
            else:
                src_ip, dst_ip = client_ip, Config.serviceIp
                src_port, dst_port = client_port, service_port
            packet_flags = rng.choice(tcp_flags) if protocol == "TCP" else None

            flows.append(WebRecordData(
                start_time=(start + timedelta(milliseconds=index * 5))
                .isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                duration_ms=rng.randint(1, 50),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                packets=rng.randint(1, 20),
                bytes=rng.randint(40, 1500),
                tcp_flags=packet_flags,
            ))

        return flows

    def test_process_5000_random_flows(self):
        flows = self.generate_flows()
        flow_handler = FlowProcessor()
        alert_crafter = AlertCrafterLogic()
        alert_crafter.alertQueue = []
        flow_handler.SetAlertCrafter(alert_crafter)

        with redirect_stdout(StringIO()):
            start_time = perf_counter()
            for flow in flows:
                flow_handler.ClassifyFlow(flow)
            elapsed = perf_counter() - start_time

        self.assertEqual(len(flows), self.flow_count)
        self.assertGreater(elapsed, 0)

        alerts = [asdict(alert) for alert in alert_crafter.alertQueue]
        print(f"Processed {len(flows)} flows in {elapsed:.3f} seconds.")
        print(f"Generated {len(alerts)} alerts:")
        #print(json.dumps(alerts, indent=2))


if __name__ == "__main__":
    main()