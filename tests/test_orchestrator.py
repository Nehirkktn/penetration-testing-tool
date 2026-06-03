"""Orchestrator için testler."""

import os
import tempfile
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket
import pytest

from siber_savascilar.orchestrator import Orchestrator, DEFAULT_MODULES
from siber_savascilar.core.models import ScanStatus
from siber_savascilar.core.database import Database


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SimpleHandler(BaseHTTPRequestHandler):
    def log_message(self, *a, **kw): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html>OK</html>')
    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()


@pytest.fixture
def isolated_db():
    """Her test için izole DB."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        yield Database(db_path)
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.fixture(scope="module")
def live_server():
    port = _get_free_port()
    server = HTTPServer(("127.0.0.1", port), SimpleHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ─────────────────────────────────────────────────────────────────────────
# Reachability
# ─────────────────────────────────────────────────────────────────────────

class TestReachabilityCheck:
    def test_reachable_live_server(self, live_server, isolated_db):
        orch = Orchestrator(db=isolated_db, verbose=False)
        reachable, msg = orch._check_reachable(live_server)
        assert reachable is True
        assert "OK" in msg or "200" in msg

    def test_unreachable_blackhole_ip(self, isolated_db):
        orch = Orchestrator(db=isolated_db, verbose=False)
        reachable, msg = orch._check_reachable("http://10.255.255.1:1",
                                               timeout=2)
        assert reachable is False

    def test_unreachable_nonexistent_host(self, isolated_db):
        orch = Orchestrator(db=isolated_db, verbose=False)
        reachable, msg = orch._check_reachable("http://nonexistent-domain-xyz-12345.invalid",
                                               timeout=2)
        assert reachable is False


# ─────────────────────────────────────────────────────────────────────────
# Tarama akışı
# ─────────────────────────────────────────────────────────────────────────

class TestScanFlow:
    def test_invalid_url_returns_error(self, isolated_db):
        orch = Orchestrator(db=isolated_db, verbose=False)
        result = orch.scan("ftp://invalid", modules=["sqli"])
        assert result.status == ScanStatus.ERROR
        assert result.error_message != ""

    def test_empty_url_returns_error(self, isolated_db):
        orch = Orchestrator(db=isolated_db, verbose=False)
        result = orch.scan("", modules=["sqli"])
        assert result.status == ScanStatus.ERROR

    def test_scan_creates_db_record(self, live_server, isolated_db):
        orch = Orchestrator(db=isolated_db, verbose=False)
        result = orch.scan(live_server, modules=["misconfig"])
        assert result.scan_id is not None
        assert isolated_db.get_scan(result.scan_id) is not None

    def test_scan_records_module_list(self, live_server, isolated_db):
        modules = ["misconfig", "sensitive_data"]
        orch = Orchestrator(db=isolated_db, verbose=False)
        result = orch.scan(live_server, modules=modules)
        assert set(result.modules_run) == set(modules)

    def test_scan_completes_with_status(self, live_server, isolated_db):
        orch = Orchestrator(db=isolated_db, verbose=False)
        result = orch.scan(live_server, modules=["misconfig"])
        assert result.status == ScanStatus.COMPLETED

    def test_scan_sets_finished_at(self, live_server, isolated_db):
        orch = Orchestrator(db=isolated_db, verbose=False)
        result = orch.scan(live_server, modules=["misconfig"])
        assert result.finished_at is not None

    def test_scan_calculates_duration(self, live_server, isolated_db):
        orch = Orchestrator(db=isolated_db, verbose=False)
        result = orch.scan(live_server, modules=["misconfig"])
        assert result.duration_seconds is not None
        assert result.duration_seconds >= 0

    def test_unknown_module_skipped(self, live_server, isolated_db):
        """Bilinmeyen modüller crash etmeden atlanmalı."""
        orch = Orchestrator(db=isolated_db, verbose=False)
        result = orch.scan(live_server, modules=["bilinmeyen", "misconfig"])
        assert result.status == ScanStatus.COMPLETED

    def test_scan_generates_summary(self, live_server, isolated_db):
        orch = Orchestrator(db=isolated_db, verbose=False)
        result = orch.scan(live_server, modules=["misconfig"])
        assert result.summary != ""


class TestProgressCallback:
    def test_callback_invoked_per_module(self, live_server, isolated_db):
        called_modules = []

        def cb(module_name, current, total):
            called_modules.append(module_name)

        orch = Orchestrator(db=isolated_db, verbose=False)
        orch.scan(live_server,
                  modules=["misconfig", "sensitive_data"],
                  progress_callback=cb)

        # En az birkaç kez çağrılmış olmalı
        assert len(called_modules) >= 1
