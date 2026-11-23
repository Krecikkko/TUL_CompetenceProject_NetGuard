from datetime import datetime, timedelta

import pytest
from model_bakery import baker
from rest_framework.test import APIClient

from core.models import (
    NetworkFlow,
    TimeWindow,
    Detection,
)

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def network_flow_tcp(db):
    return baker.make(
        NetworkFlow,
        start_timestamp_us=datetime.fromisoformat("2026-11-23T09:00:01Z"),
        duration_us=timedelta(microseconds=500000),
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        source_port=54321,
        destination_port=22,
        protocol="TCP",
        packet_count=100,
        byte_count=15000,
        tcp_flags=24,
    )

@pytest.fixture
def network_flow_icmp(db):
    return baker.make(
        NetworkFlow,
        start_timestamp_us=datetime.fromisoformat("2026-11-23T09:00:00Z"),
        duration_us=timedelta(microseconds=80000),
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        source_port=None,
        destination_port=None,
        protocol="ICMP",
        packet_count=1,
        byte_count=50,
        tcp_flags=None,
    )


@pytest.fixture
def time_window(db):
    return baker.make(
        TimeWindow,
        start_timestamp_us=datetime.fromisoformat("2026-11-23T09:00:00Z"),
        duration_us=timedelta(seconds=60),
        type=TimeWindow.WindowType.SO1DE1,
    )

@pytest.fixture
def detection(db, time_window):
    return baker.make(
        Detection,
        method="TEST",
        rule_id="TEST-001",
        detected_at_us=datetime.fromisoformat("2026-11-23T09:01:00Z"),
        type="PORT_SCAN",
        severity=Detection.Severity.HIGH,
        confidence=0.95,
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        key_feature_values={
            "packet_count": 101,
            "unique_ports": 1,
        },
        explanation="Suspicious port scanning activity",
        window=time_window,
    )
