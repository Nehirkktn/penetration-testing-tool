"""ScenarioScanner için detaylı testler — Muhammed'in YAML motoru."""

import os
import threading
import time
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest

from siber_savascilar.scanners.scenario_scanner import ScenarioScanner, HAS_YAML
from siber_savascilar.core.models import Severity, VulnType


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, *a, **kw): pass

    def do_GET(self):
        if self.path == "/admin-panel-tr":
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('X-Test', 'present')
            self.end_headers()
            self.wfile.write(b'<h1>Yonetim Paneli</h1>')
        elif self.path == "/.git/HEAD":
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'ref: refs/heads/main')
        elif self.path == "/safe":
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Safe')
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def test_server():
    port = _get_free_port()
    server = HTTPServer(("127.0.0.1", port), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def scenarios_dir(tmp_path):
    """Geçici scenarios dizini."""
    return str(tmp_path)


def _write_scenario(scenarios_dir, filename, content):
    path = os.path.join(scenarios_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# ─────────────────────────────────────────────────────────────────────────
# Loading
# ─────────────────────────────────────────────────────────────────────────

class TestScenarioLoading:
    def test_loads_yaml_file(self, scenarios_dir):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "test.yaml", """
id: test-scenario
info:
  name: "Test"
  severity: "Low"
requests:
  - method: GET
    path: ["{{target_url}}/test"]
    matchers:
      - type: status
        status: [200]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        scenarios = scanner._load_scenarios()
        assert len(scenarios) == 1

    def test_loads_yml_extension_also(self, scenarios_dir):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "test.yml", """
id: test
info: {name: "T", severity: "Low"}
requests: [{method: GET, path: ["x"], matchers: [{type: status, status: [200]}]}]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        scenarios = scanner._load_scenarios()
        assert len(scenarios) == 1

    def test_loads_multiple_scenarios(self, scenarios_dir):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        for i in range(3):
            _write_scenario(scenarios_dir, f"test{i}.yaml", f"""
id: test-{i}
info: {{name: "T{i}", severity: "Low"}}
requests: [{{method: GET, path: ["x"], matchers: [{{type: status, status: [200]}}]}}]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        scenarios = scanner._load_scenarios()
        assert len(scenarios) == 3

    def test_skips_invalid_yaml(self, scenarios_dir):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "broken.yaml", "this is: : : broken yaml [[[")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        scenarios = scanner._load_scenarios()
        # Invalid yaml atlanmalı
        assert len(scenarios) == 0

    def test_skips_yaml_without_requests(self, scenarios_dir):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "no_req.yaml", "id: x\ninfo: {name: 'X'}")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        scenarios = scanner._load_scenarios()
        assert len(scenarios) == 0


# ─────────────────────────────────────────────────────────────────────────
# Matcher değerlendirme
# ─────────────────────────────────────────────────────────────────────────

class TestStatusMatcher:
    def test_status_match_success(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: admin-tr
info:
  name: "Türkçe admin panel"
  severity: "High"
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers:
      - type: status
        status: [200]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert len(vulns) >= 1

    def test_status_no_match(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: no-match
info:
  name: "Beklenen 500"
  severity: "Low"
requests:
  - method: GET
    path: ["{{target_url}}/safe"]
    matchers:
      - type: status
        status: [500]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert len(vulns) == 0


class TestWordMatcher:
    def test_word_match_success(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: word
info:
  name: "Word"
  severity: "Medium"
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers:
      - type: word
        words: ["Yonetim"]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert len(vulns) >= 1

    def test_word_condition_and(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: word-and
info: {name: "Word AND", severity: "Low"}
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers:
      - type: word
        condition: and
        words: ["Yonetim", "Paneli"]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert len(vulns) >= 1

    def test_word_condition_and_one_missing(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: word-and-fail
info: {name: "Word AND fail", severity: "Low"}
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers:
      - type: word
        condition: and
        words: ["Yonetim", "BulunmayanKelime"]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert len(vulns) == 0


class TestRegexMatcher:
    def test_regex_match(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: git-exposure
info: {name: "Git", severity: "High"}
requests:
  - method: GET
    path: ["{{target_url}}/.git/HEAD"]
    matchers:
      - type: regex
        regex: ["^ref: refs/heads/"]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert len(vulns) >= 1


class TestHeaderMatcher:
    def test_header_match(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: header
info: {name: "Header", severity: "Low"}
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers:
      - type: header
        headers:
          X-Test: present
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert len(vulns) >= 1


class TestMatcherConditions:
    def test_and_condition_requires_all(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: and-cond
info: {name: "AND", severity: "Low"}
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: status
        status: [500]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        # status hem 200 hem 500 olamaz
        assert len(vulns) == 0

    def test_or_condition_any_matches(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: or-cond
info: {name: "OR", severity: "Low"}
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers-condition: or
    matchers:
      - type: status
        status: [500]
      - type: status
        status: [200]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert len(vulns) >= 1


class TestVulnerabilityFields:
    def test_severity_from_yaml(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: sev-critical
info: {name: "Critical", severity: "Critical"}
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers:
      - type: status
        status: [200]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert vulns[0].severity == Severity.CRITICAL

    def test_default_severity_for_invalid(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: invalid-sev
info: {name: "X", severity: "ÇokKritik"}
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers:
      - type: status
        status: [200]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        # Geçersiz severity → Medium default
        assert vulns[0].severity == Severity.MEDIUM

    def test_vuln_type_is_custom(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: custom-vt
info: {name: "X", severity: "Low"}
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers: [{type: status, status: [200]}]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert vulns[0].vuln_type == VulnType.CUSTOM_SCENARIO

    def test_details_include_scenario_metadata(self, scenarios_dir, test_server):
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: meta-test
info:
  name: "Meta"
  severity: "Low"
  author: "test-author"
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers: [{type: status, status: [200]}]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        assert vulns[0].details.get("scenario_id") == "meta-test"
        assert vulns[0].details.get("author") == "test-author"


class TestTargetURLSubstitution:
    def test_target_url_replaced(self, scenarios_dir, test_server):
        """{{target_url}} placeholder doğru değiştirilmeli."""
        if not HAS_YAML:
            pytest.skip("PyYAML kurulu değil")
        _write_scenario(scenarios_dir, "s.yaml", """
id: sub
info: {name: "Sub", severity: "Low"}
requests:
  - method: GET
    path: ["{{target_url}}/admin-panel-tr"]
    matchers: [{type: status, status: [200]}]
""")
        scanner = ScenarioScanner(scenarios_dir=scenarios_dir, verbose=False)
        vulns = scanner.scan(test_server)
        # Target URL'i {{target_url}} olarak değil gerçek URL olarak içermeli
        assert "{{target_url}}" not in vulns[0].target
        assert test_server in vulns[0].target
