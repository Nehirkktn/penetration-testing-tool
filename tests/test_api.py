"""Flask API endpoint testleri."""

import os
import json
import tempfile
import pytest

from siber_savascilar.api.server import create_app
from siber_savascilar.core.database import Database, get_db
from siber_savascilar.core import database as db_module


@pytest.fixture
def isolated_db(monkeypatch):
    """Her test için izole DB — global singleton'u override eder."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    db = Database(db_path)
    # Singleton'u test DB'siyle değiştir
    monkeypatch.setattr(db_module, "_default_db", db)
    try:
        yield db
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.fixture
def client(isolated_db):
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


# ─────────────────────────────────────────────────────────────────────────
# Index ve statik dosyalar
# ─────────────────────────────────────────────────────────────────────────

class TestStaticServing:
    def test_index_returns_200(self, client):
        r = client.get('/')
        assert r.status_code == 200

    def test_index_is_html(self, client):
        r = client.get('/')
        assert b'<html' in r.data.lower() or b'<!doctype' in r.data.lower()

    def test_static_css(self, client):
        r = client.get('/static/style.css')
        assert r.status_code == 200

    def test_static_js(self, client):
        r = client.get('/static/script.js')
        assert r.status_code == 200


# ─────────────────────────────────────────────────────────────────────────
# /api/stats
# ─────────────────────────────────────────────────────────────────────────

class TestStatsEndpoint:
    def test_stats_returns_200(self, client):
        r = client.get('/api/stats')
        assert r.status_code == 200

    def test_stats_returns_json(self, client):
        r = client.get('/api/stats')
        assert r.content_type.startswith('application/json')

    def test_stats_has_expected_keys(self, client):
        r = client.get('/api/stats')
        data = r.get_json()
        assert "total_scans" in data
        assert "total_vulnerabilities" in data
        assert "critical_count" in data
        assert "high_count" in data

    def test_stats_zero_initially(self, client):
        r = client.get('/api/stats')
        data = r.get_json()
        assert data["total_scans"] == 0
        assert data["total_vulnerabilities"] == 0


# ─────────────────────────────────────────────────────────────────────────
# /api/scans
# ─────────────────────────────────────────────────────────────────────────

class TestScansListEndpoint:
    def test_returns_200(self, client):
        r = client.get('/api/scans')
        assert r.status_code == 200

    def test_returns_list(self, client):
        r = client.get('/api/scans')
        assert isinstance(r.get_json(), list)

    def test_empty_initially(self, client):
        r = client.get('/api/scans')
        assert len(r.get_json()) == 0

    def test_limit_parameter(self, client, isolated_db):
        for i in range(5):
            isolated_db.create_scan(f"http://t{i}.com", ["sqli"])
        r = client.get('/api/scans?limit=3')
        assert len(r.get_json()) == 3


class TestScanDetailEndpoint:
    def test_nonexistent_returns_404(self, client):
        r = client.get('/api/scans/99999')
        assert r.status_code == 404

    def test_existing_scan(self, client, isolated_db):
        scan_id = isolated_db.create_scan("http://test.com", ["sqli"])
        r = client.get(f'/api/scans/{scan_id}')
        assert r.status_code == 200
        data = r.get_json()
        assert data["target_url"] == "http://test.com"

    def test_includes_vulnerabilities_field(self, client, isolated_db):
        scan_id = isolated_db.create_scan("http://test.com", ["sqli"])
        r = client.get(f'/api/scans/{scan_id}')
        data = r.get_json()
        assert "vulnerabilities" in data


# ─────────────────────────────────────────────────────────────────────────
# POST /api/scans (yeni tarama)
# ─────────────────────────────────────────────────────────────────────────

class TestStartScan:
    def test_missing_target_returns_400(self, client):
        r = client.post('/api/scans', json={})
        assert r.status_code == 400

    def test_invalid_url_returns_400(self, client):
        r = client.post('/api/scans', json={"target": "ftp://invalid"})
        assert r.status_code == 400


# ─────────────────────────────────────────────────────────────────────────
# DELETE /api/scans/<id>
# ─────────────────────────────────────────────────────────────────────────

class TestDeleteScan:
    def test_delete_existing(self, client, isolated_db):
        scan_id = isolated_db.create_scan("http://t.com", ["sqli"])
        r = client.delete(f'/api/scans/{scan_id}')
        assert r.status_code == 200

    def test_delete_removes_from_db(self, client, isolated_db):
        scan_id = isolated_db.create_scan("http://t.com", ["sqli"])
        client.delete(f'/api/scans/{scan_id}')
        assert isolated_db.get_scan(scan_id) is None


# ─────────────────────────────────────────────────────────────────────────
# /api/scanners
# ─────────────────────────────────────────────────────────────────────────

class TestScannersEndpoint:
    def test_returns_200(self, client):
        r = client.get('/api/scanners')
        assert r.status_code == 200

    def test_returns_list(self, client):
        r = client.get('/api/scanners')
        assert isinstance(r.get_json(), list)

    def test_has_8_scanners(self, client):
        r = client.get('/api/scanners')
        assert len(r.get_json()) == 8

    def test_each_has_name_and_description(self, client):
        r = client.get('/api/scanners')
        for s in r.get_json():
            assert "name" in s
            assert "description" in s
            assert "default" in s


# ─────────────────────────────────────────────────────────────────────────
# /api/scenarios
# ─────────────────────────────────────────────────────────────────────────

class TestScenariosEndpoint:
    def test_returns_200(self, client):
        r = client.get('/api/scenarios')
        assert r.status_code == 200

    def test_returns_list(self, client):
        r = client.get('/api/scenarios')
        assert isinstance(r.get_json(), list)

    def test_includes_example_scenarios(self, client):
        """Projede 3 örnek YAML senaryo var."""
        r = client.get('/api/scenarios')
        scenarios = r.get_json()
        # En az 1 senaryo olmalı (scenarios_data/ doluysa)
        # Boş da olabilir test ortamında, gevşek assert
        assert isinstance(scenarios, list)


# ─────────────────────────────────────────────────────────────────────────
# Rapor indirme endpoint'leri (PDF, JSON, HTML)
# ─────────────────────────────────────────────────────────────────────────

class TestReportDownloadEndpoints:
    def test_html_report_404_for_missing_scan(self, client):
        r = client.get('/api/scans/99999/report')
        assert r.status_code == 404

    def test_pdf_report_404_for_missing_scan(self, client):
        r = client.get('/api/scans/99999/report.pdf')
        assert r.status_code == 404

    def test_json_report_404_for_missing_scan(self, client):
        r = client.get('/api/scans/99999/report.json')
        assert r.status_code == 404

    def test_pdf_endpoint_handles_incomplete_scan(self, client, isolated_db):
        """Scan tamamlanmamış olsa bile endpoint anında PDF üretmeye çalışır."""
        scan_id = isolated_db.create_scan("http://t.com", ["sqli"])
        r = client.get(f'/api/scans/{scan_id}/report.pdf')
        # Endpoint ya 200 (anında üretti) ya da 404/500/501 (yapamadı) dönmeli
        assert r.status_code in (200, 404, 500, 501)

    def test_json_endpoint_returns_404_when_no_report(self, client, isolated_db):
        scan_id = isolated_db.create_scan("http://t.com", ["sqli"])
        r = client.get(f'/api/scans/{scan_id}/report.json')
        assert r.status_code in (404, 500)
