import pytest

# Endpoints tested:
# - /api/flows/
# - /api/flows/<int:pk>/

# single flow
@pytest.mark.django_db
def test_network_flow_details(api_client, network_flow_tcp):
    response = api_client.get(f"/api/flows/{network_flow_tcp.id}/")

    assert response.status_code == 200

    data = response.json()
    correct_flags = {
        "CWR": False,
        "ECE": False,
        "URG": False,
        "ACK": True,
        "PSH": True,
        "RST": False,
        "SYN": False,
        "FIN": False,
    }

    assert data["start_timestamp_us"] == "2026-11-23T09:00:01Z"
    assert data["duration_us"] == "00:00:00.500000"
    assert data["source_ip"] == "192.168.1.10"
    assert data["destination_ip"] == "10.0.0.5"
    assert data["source_port"] == 54321
    assert data["destination_port"] == 22
    assert data["protocol"] == "TCP"
    assert data["packet_count"] == 100
    assert data["byte_count"] == 15000
    assert data["tcp_flags"] == correct_flags

# single flow from list
@pytest.mark.django_db
def test_network_flow_details_from_list(
    api_client, 
    network_flow_tcp, 
    network_flow_icmp
):
    response = api_client.get("/api/flows/")

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 2

    result = data["results"][0]
    correct_flags = {
        "CWR": False,
        "ECE": False,
        "URG": False,
        "ACK": True,
        "PSH": True,
        "RST": False,
        "SYN": False,
        "FIN": False,
    }

    assert result["start_timestamp_us"] == "2026-11-23T09:00:01Z"
    assert result["duration_us"] == "00:00:00.500000"
    assert result["source_ip"] == "192.168.1.10"
    assert result["destination_ip"] == "10.0.0.5"
    assert result["source_port"] == 54321
    assert result["destination_port"] == 22
    assert result["protocol"] == "TCP"
    assert result["packet_count"] == 100
    assert result["byte_count"] == 15000
    assert result["tcp_flags"] == correct_flags

# single flow with Nones
@pytest.mark.django_db
def test_network_flow_icmp(api_client, network_flow_icmp):
    response = api_client.get(f"/api/flows/{network_flow_icmp.id}/")

    assert response.status_code == 200

    data = response.json()

    assert data["start_timestamp_us"] == "2026-11-23T09:00:00Z"
    assert data["duration_us"] == "00:00:00.080000"
    assert data["source_ip"] == "192.168.1.10"
    assert data["destination_ip"] == "10.0.0.5"
    assert data["source_port"] is None
    assert data["destination_port"] is None
    assert data["protocol"] == "ICMP"
    assert data["packet_count"] == 1
    assert data["byte_count"] == 50
    assert data["tcp_flags"] is None
