"""
Backend unit and integration tests for portscanner.py.

Run with:
    pytest tests/ -v
"""

import pytest
from fastapi.testclient import TestClient

# Import the FastAPI app and scanner functions
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from portscanner import app, _is_valid_target, scan_port, analyze_port, PORTS, SECURITY_INTEL

client = TestClient(app)


# ---------------------------------------------------------------------------
# _is_valid_target
# ---------------------------------------------------------------------------
class TestIsValidTarget:
    def test_valid_ipv4(self):
        assert _is_valid_target("192.168.1.1")
        assert _is_valid_target("10.0.0.1")
        assert _is_valid_target("8.8.8.8")
        assert _is_valid_target("255.255.255.255")
        assert _is_valid_target("0.0.0.0")

    def test_invalid_ipv4(self):
        assert not _is_valid_target("256.0.0.1")       # octet out of range
        assert not _is_valid_target("192.168.1")       # only 3 octets
        assert not _is_valid_target("192.168.1.1.1")   # 5 octets
        assert not _is_valid_target("abc")             # not an IP

    def test_valid_domain(self):
        assert _is_valid_target("example.com")
        assert _is_valid_target("sub.example.com")
        assert _is_valid_target("my-host.internal.co.uk")

    def test_invalid_domain(self):
        assert not _is_valid_target("localhost")           # no TLD
        assert not _is_valid_target("not valid.com")       # space
        assert not _is_valid_target("")                    # empty string


# ---------------------------------------------------------------------------
# scan_port — using localhost (safe, predictable)
# ---------------------------------------------------------------------------
class TestScanPort:
    def test_open_port_localhost(self, tmp_path):
        """Port 8000 may or may not be open on CI; just verify return shape."""
        status, rt = scan_port("127.0.0.1", 80)
        assert status in ("open", "closed", "filtered")
        if status == "open":
            assert isinstance(rt, float)
            assert rt >= 0
        else:
            assert rt is None

    def test_refused_port_returns_closed(self):
        """Port 1 is almost certainly not listening — expect closed (ECONNREFUSED)."""
        status, rt = scan_port("127.0.0.1", 1)
        # On most systems this will be closed; accept filtered too for CI environments
        assert status in ("closed", "filtered")
        assert rt is None


# ---------------------------------------------------------------------------
# analyze_port
# ---------------------------------------------------------------------------
class TestAnalyzePort:
    def test_open_port_has_risk_level(self):
        result = analyze_port(3389, "RDP", "open", 12.5)
        assert result["status"] == "open"
        assert result["risk_level"] == "critical"
        assert result["response_time_ms"] == 12.5
        assert len(result["vulnerabilities"]) > 0
        assert len(result["mitigations"]) > 0

    def test_closed_port_is_low_risk(self):
        result = analyze_port(22, "SSH", "closed", None)
        assert result["status"] == "closed"
        assert result["risk_level"] == "low"
        assert result["response_time_ms"] is None
        assert result["vulnerabilities"] == []

    def test_filtered_port_is_low_risk(self):
        result = analyze_port(3306, "MySQL", "filtered", None)
        assert result["status"] == "filtered"
        assert result["risk_level"] == "low"
        assert result["response_time_ms"] is None

    def test_unknown_port_open_gets_medium_risk(self):
        result = analyze_port(12345, "Unknown", "open", 5.0)
        assert result["status"] == "open"
        assert result["risk_level"] == "medium"   # default for unknown ports

    def test_all_required_fields_present(self):
        result = analyze_port(80, "HTTP", "open", 10.0)
        required_keys = {"port", "service", "status", "risk_level", "response_time_ms",
                         "description", "vulnerabilities", "attack_vectors", "mitigations", "details"}
        assert required_keys.issubset(result.keys())

    @pytest.mark.parametrize("port,expected_risk", [
        (21,   "critical"),
        (23,   "critical"),
        (445,  "critical"),
        (3389, "critical"),
        (6379, "critical"),
        (443,  "low"),
        (993,  "low"),
        (995,  "low"),
        (22,   "medium"),
        (80,   "medium"),
    ])
    def test_risk_levels_for_known_ports(self, port, expected_risk):
        service = PORTS.get(port, "Unknown")
        result = analyze_port(port, service, "open", 5.0)
        assert result["risk_level"] == expected_risk, (
            f"Port {port} expected {expected_risk} but got {result['risk_level']}"
        )


# ---------------------------------------------------------------------------
# API integration tests
# ---------------------------------------------------------------------------
class TestHealthEndpoint:
    def test_health_returns_ok(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "timestamp" in data


class TestScanEndpoint:
    def test_missing_target_returns_422(self):
        response = client.get("/scan")
        assert response.status_code == 422   # FastAPI validation error

    def test_invalid_target_returns_400(self):
        response = client.get("/scan?target=not_a_valid_target!!!")
        assert response.status_code == 400
        assert "detail" in response.json()

    def test_invalid_ip_returns_400(self):
        response = client.get("/scan?target=999.999.999.999")
        assert response.status_code == 400

    def test_nonexistent_domain_returns_400(self):
        response = client.get("/scan?target=this-domain-does-not-exist-xyz.invalid")
        assert response.status_code == 400

    def test_scan_localhost_returns_valid_structure(self):
        """Scanning localhost is safe; verify response structure."""
        response = client.get("/scan?target=127.0.0.1", timeout=60)
        assert response.status_code == 200
        data = response.json()

        # Top-level fields
        assert data["target"] == "127.0.0.1"
        assert data["resolved_ip"] == "127.0.0.1"
        assert "scanned_at" in data
        assert isinstance(data["duration_seconds"], float)
        assert data["total_ports"] == len(PORTS)

        # Results array
        results = data["results"]
        assert len(results) == len(PORTS)

        # Verify each result has required fields
        for r in results:
            assert r["port"] in PORTS
            assert r["status"] in ("open", "closed", "filtered")
            assert r["risk_level"] in ("low", "medium", "high", "critical")
            assert "vulnerabilities" in r
            assert "mitigations" in r
            assert "response_time_ms" in r

        # Results should be sorted by port number
        ports_in_order = [r["port"] for r in results]
        assert ports_in_order == sorted(ports_in_order)

    def test_scan_covers_all_required_ports(self):
        """Verify all 28 required ports are scanned."""
        required_ports = {
            20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            443, 445, 587, 993, 995, 1433, 1521, 1723, 2049,
            3306, 3389, 5432, 5900, 6379, 8080, 8443,
        }
        assert set(PORTS.keys()) == required_ports


# ---------------------------------------------------------------------------
# Security intelligence completeness
# ---------------------------------------------------------------------------
class TestSecurityIntel:
    def test_all_ports_have_intel(self):
        """Every port in PORTS should have an entry in SECURITY_INTEL."""
        missing = [p for p in PORTS if p not in SECURITY_INTEL]
        assert not missing, f"Missing SECURITY_INTEL for ports: {missing}"

    def test_intel_has_required_fields(self):
        required = {"description", "vulnerabilities", "attack_vectors", "mitigations", "open_risk"}
        for port, intel in SECURITY_INTEL.items():
            missing = required - intel.keys()
            assert not missing, f"Port {port} intel missing fields: {missing}"

    def test_risk_levels_are_valid(self):
        valid = {"low", "medium", "high", "critical"}
        for port, intel in SECURITY_INTEL.items():
            assert intel["open_risk"] in valid, (
                f"Port {port} has invalid open_risk: {intel['open_risk']}"
            )
