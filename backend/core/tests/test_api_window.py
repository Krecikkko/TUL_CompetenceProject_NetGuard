import pytest

# Endpoints tested:
# - /api/flows/<int:pk>/windows/
# - /api/windows/
# - /api/windows/<int:pk>/
# - /api/windows/<int:pk>/statistics/
# - /api/windows/<int:pk>/flows/

@pytest.mark.django_db
def test_window_details(api_client, time_window):
    response = api_client.get(f"/api/windows/{time_window.id}/")

    assert response.status_code == 200
    
    data = response.json()

    assert data["start_timestamp_us"] == "2026-11-23T09:00:00Z"
    assert data["duration_us"] == "00:01:00"
    assert data["type"] == "SO1DE1"

@pytest.mark.django_db
def test_window_details_from_list(api_client, time_window):
    response = api_client.get(f"/api/windows/")

    assert response.status_code == 200
    
    data = response.json()

    assert data["count"] == 1

    result = data["results"][0]

    assert result["start_timestamp_us"] == "2026-11-23T09:00:00Z"
    assert result["duration_us"] == "00:01:00"
    assert result["type"] == "SO1DE1"

@pytest.mark.django_db
def test_window_flows_relationships(
    api_client,
    time_window,
    network_flow_tcp,
    network_flow_icmp,
):
    # adding flows to window
    time_window.network_flows.add(
        network_flow_tcp,
        network_flow_icmp,
    )

    # window -> flows relationship
    response = api_client.get(f"/api/windows/{time_window.id}/flows/")
    
    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 2

    result_tcp = data["results"][0]

    assert result_tcp["start_timestamp_us"] == "2026-11-23T09:00:01Z"
    assert result_tcp["protocol"] == "TCP"

    result_icmp = data["results"][1]

    assert result_icmp["start_timestamp_us"] == "2026-11-23T09:00:00Z"
    assert result_icmp["protocol"] == "ICMP"

    # tcp flow -> window relationship
    response = api_client.get(f"/api/flows/{network_flow_tcp.id}/windows/")

    assert response.status_code == 200
    
    data = response.json()

    assert data["count"] == 1

    result_tcp_window = data["results"][0]

    assert result_tcp_window["start_timestamp_us"] == "2026-11-23T09:00:00Z"
    assert result_tcp_window["duration_us"] == "00:01:00"
    assert result_tcp_window["type"] == "SO1DE1"

    # icmp flow -> window relationship
    response = api_client.get(f"/api/flows/{network_flow_icmp.id}/windows/")

    assert response.status_code == 200
    
    data = response.json()

    assert data["count"] == 1

    result_tcp_window = data["results"][0]

    assert result_tcp_window["start_timestamp_us"] == "2026-11-23T09:00:00Z"
    assert result_tcp_window["duration_us"] == "00:01:00"
    assert result_tcp_window["type"] == "SO1DE1"

@pytest.mark.django_db
def test_window_stats(
    api_client,
    time_window,
    network_flow_tcp,
    network_flow_icmp,
):
    # adding flows to window
    time_window.network_flows.add(
        network_flow_tcp,
        network_flow_icmp,
    )

    #verifying stats
    response = api_client.get(f"/api/windows/{time_window.id}/statistics/")
        
    assert response.status_code == 200

    data = response.json()

    assert data["total_network_flows"] == 2
    assert pytest.approx(data["packets_per_second"], abs=0.00001) == 1.68333
    assert pytest.approx(data["bytes_per_second"], abs=0.00001) == 250.83333
    assert data["active_connections"] == 2

