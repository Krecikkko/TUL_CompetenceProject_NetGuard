import pytest

# Endpoints tested:
# - /api/windows/<int:pk>/detection/
# - /api/detections/
# - /api/detections/<int:pk>/
# - /api/detections/<int:pk>/window/

@pytest.mark.django_db
def test_detection_details(
    api_client,
    detection,
    time_window
):
    response = api_client.get(f"/api/detections/{detection.id}/")

    assert response.status_code == 200
    
    data = response.json()

    assert data["method"] == "TEST"
    assert data["rule_id"] == "TEST-001"
    assert data["detected_at_us"] == "2026-11-23T09:01:00Z"
    assert data["type"] == "PORT_SCAN"
    assert data["severity"] == "HIGH"
    assert data["confidence"] == 0.95
    assert data["source_ip"] == "192.168.1.10"
    assert data["destination_ip"] == "10.0.0.5"
    assert data["key_feature_values"] == {
        "packet_count": 101,
        "unique_ports": 1,
    }
    assert data["explanation"] == "Suspicious port scanning activity"
    assert data["window"] == time_window.id
    
@pytest.mark.django_db
def test_detection_details_from_list(
    api_client,
    detection,
    time_window
):
    response = api_client.get(f"/api/detections/")

    assert response.status_code == 200
    
    data = response.json()
    
    assert data["count"] == 1

    result = data["results"][0]

    assert result["method"] == "TEST"
    assert result["rule_id"] == "TEST-001"
    assert result["detected_at_us"] == "2026-11-23T09:01:00Z"
    assert result["type"] == "PORT_SCAN"
    assert result["severity"] == "HIGH"
    assert result["confidence"] == 0.95
    assert result["source_ip"] == "192.168.1.10"
    assert result["destination_ip"] == "10.0.0.5"
    assert result["key_feature_values"] == {
        "packet_count": 101,
        "unique_ports": 1,
    }
    assert result["explanation"] == "Suspicious port scanning activity"
    assert result["window"] == time_window.id

@pytest.mark.django_db
def test_detection_window(
    api_client,
    detection,
    time_window
):
    # detection -> window relationship
    response = api_client.get(f"/api/detections/{detection.id}/window/")

    assert response.status_code == 200
    
    data = response.json()

    assert data["start_timestamp_us"] == "2026-11-23T09:00:00Z"
    assert data["duration_us"] == "00:01:00"
    assert data["type"] == "SO1DE1"

    # window -> detection relationship
    response = api_client.get(f"/api/windows/{time_window.id}/detection/")
    
    assert response.status_code == 200
    
    data = response.json()

    assert data["method"] == "TEST"
    assert data["rule_id"] == "TEST-001"
    assert data["detected_at_us"] == "2026-11-23T09:01:00Z"
    assert data["type"] == "PORT_SCAN"
    assert data["severity"] == "HIGH"
    assert data["confidence"] == 0.95
    assert data["source_ip"] == "192.168.1.10"
    assert data["destination_ip"] == "10.0.0.5"
    assert data["key_feature_values"] == {
        "packet_count": 101,
        "unique_ports": 1,
    }
    assert data["explanation"] == "Suspicious port scanning activity"
    assert data["window"] == time_window.id
