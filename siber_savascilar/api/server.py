"""
Flask Backend API
==================

Şevval Duran'ın frontend prototipini (index.html, style.css, script.js)
gerçek bir backend'e bağlayan API katmanı.

Endpoint'ler:
    GET  /                         → Ana panel
    GET  /api/stats                → Dashboard istatistikleri
    GET  /api/scans                → Tüm taramaları listele
    GET  /api/scans/<id>           → Tek bir tarama detayı
    GET  /api/scans/<id>/report    → HTML raporu görüntüle
    POST /api/scans                → Yeni tarama başlat
    DELETE /api/scans/<id>         → Tarama sil
    GET  /api/scanners             → Mevcut tarayıcı modülleri
    GET  /api/scenarios            → Yüklü YAML senaryolar
"""

import os
import threading
from datetime import datetime
from flask import (
    Flask, jsonify, request, send_file, send_from_directory,
    render_template_string, abort
)

from ..orchestrator import Orchestrator, DEFAULT_MODULES
from ..reporting import ReportGenerator
from ..scanners import SCANNER_REGISTRY
from ..core.database import get_db
from ..core.validators import URLValidator


# Web statik dosyaları proje kökünde web/ klasöründe
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB_DIR = os.path.join(PROJECT_ROOT, "web")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["JSON_AS_ASCII"] = False

    db = get_db()

    # ── Ana sayfa: Şevval'in frontend'i ───────────────────────────────────

    @app.route("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.route("/static/<path:filename>")
    def static_files(filename):
        return send_from_directory(WEB_DIR, filename)

    # ── API ───────────────────────────────────────────────────────────────

    @app.route("/api/stats")
    def stats():
        """Dashboard istatistikleri."""
        return jsonify(db.get_stats())

    @app.route("/api/scans", methods=["GET"])
    def list_scans():
        """Tüm taramaları listele."""
        limit = request.args.get("limit", 50, type=int)
        scans = db.list_scans(limit=limit)
        return jsonify(scans)

    @app.route("/api/scans/<int:scan_id>", methods=["GET"])
    def get_scan(scan_id):
        """Tek bir taramanın detayı."""
        scan = db.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "Tarama bulunamadı"}), 404
        scan["vulnerabilities"] = db.get_vulnerabilities(scan_id)
        scan["report"] = db.get_report(scan_id)
        return jsonify(scan)

    @app.route("/api/scans/<int:scan_id>/report")
    def view_report(scan_id):
        """HTML raporu doğrudan görüntüle (tarayıcıda render)."""
        report = db.get_report(scan_id)
        if not report or not report.get("html_path"):
            return jsonify({"error": "Rapor bulunamadı"}), 404

        html_path = report["html_path"]
        if not os.path.exists(html_path):
            return jsonify({"error": "Rapor dosyası kayıp"}), 404

        # HTML dosyasını oku, sağ üst "PDF indir" butonu enjekte et
        try:
            with open(html_path, "r", encoding="utf-8") as f:
                html = f.read()
            download_button = _render_download_button(scan_id)
            # </body>'den önce ekle
            html = html.replace("</body>", download_button + "\n</body>")
            return html, 200, {"Content-Type": "text/html; charset=utf-8"}
        except Exception:
            return send_file(html_path)

    @app.route("/api/scans/<int:scan_id>/report.pdf")
    def download_pdf(scan_id):
        """PDF raporunu indir. Yoksa anında üret."""
        scan = db.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "Tarama bulunamadı"}), 404

        # Mevcut PDF dosyalarını ara
        pdf_files = [f for f in os.listdir(REPORTS_DIR)
                     if f.startswith(f"rapor_{scan_id}_") and f.endswith(".pdf")]

        if pdf_files:
            pdf_path = os.path.join(REPORTS_DIR, sorted(pdf_files)[-1])
            return send_file(pdf_path, as_attachment=True,
                             download_name=f"rapor_{scan_id}.pdf",
                             mimetype="application/pdf")

        # PDF yoksa anında üret (reportlab kuruluysa)
        try:
            from ..core.models import ScanResult, Vulnerability, ScanStatus
            from datetime import datetime as _dt

            # Tarama sonucunu DB'den rebuild et
            vulns_raw = db.get_vulnerabilities(scan_id)
            result = ScanResult(
                scan_id=scan_id,
                target_url=scan["target_url"],
                status=scan["status"],
                started_at=_dt.fromisoformat(scan["started_at"])
                    if scan.get("started_at") else None,
                finished_at=_dt.fromisoformat(scan["finished_at"])
                    if scan.get("finished_at") else None,
                modules_run=(scan.get("modules_run") or "").split(","),
                open_ports=[int(p) for p in (scan.get("open_ports") or "").split(",")
                            if p.strip().isdigit()],
            )
            for v in vulns_raw:
                result.add_vulnerability(Vulnerability(
                    vuln_type=v["vuln_type"],
                    severity=v["severity"],
                    target=v["target"] or "",
                    description=v["description"] or "",
                    payload=v["payload"] or "",
                    evidence=v["evidence"] or "",
                    parameter=v["parameter"] or "",
                    cwe=v["cwe"] or "",
                    remediation=v["remediation"] or "",
                ))

            from ..reporting import ReportGenerator
            gen = ReportGenerator(output_dir=REPORTS_DIR)
            pdf_path = gen.generate_pdf(result)

            if pdf_path is None:
                return jsonify({
                    "error": "PDF üretimi için reportlab gerekli",
                    "hint": "pip install reportlab"
                }), 501

            return send_file(pdf_path, as_attachment=True,
                             download_name=f"rapor_{scan_id}.pdf",
                             mimetype="application/pdf")
        except Exception as e:
            return jsonify({"error": f"PDF üretilemedi: {e}"}), 500

    @app.route("/api/scans/<int:scan_id>/report.json")
    def download_json(scan_id):
        """JSON raporunu indir."""
        report = db.get_report(scan_id)
        if not report or not report.get("json_path"):
            return jsonify({"error": "JSON rapor bulunamadı"}), 404
        json_path = report["json_path"]
        if not os.path.exists(json_path):
            return jsonify({"error": "JSON dosyası kayıp"}), 404
        return send_file(json_path, as_attachment=True,
                         download_name=f"rapor_{scan_id}.json",
                         mimetype="application/json")

    @app.route("/api/scans", methods=["POST"])
    def start_scan():
        """Yeni tarama başlat."""
        data = request.get_json(silent=True) or {}
        target = data.get("target", "").strip()
        modules = data.get("modules") or DEFAULT_MODULES
        sync = data.get("sync", False)  # Test için senkron mod

        if not target:
            return jsonify({"error": "target alanı zorunlu"}), 400

        target = URLValidator.normalize(target)
        is_valid, msg = URLValidator.validate(target)
        if not is_valid:
            return jsonify({"error": f"Geçersiz URL: {msg}"}), 400

        # Bilinmeyen modülleri filtrele
        modules = [m for m in modules if m in SCANNER_REGISTRY]
        if not modules:
            modules = DEFAULT_MODULES

        if sync:
            result = _execute_scan(target, modules)
            return jsonify(result.to_dict())

        # Asenkron: thread'de çalıştır, hemen scan_id döndür
        scan_id_holder = {}
        ready = threading.Event()

        def run_in_background():
            scan_id_holder["result"] = _execute_scan(target, modules,
                                                     ready_event=ready)

        thread = threading.Thread(target=run_in_background, daemon=True)
        thread.start()

        # Scan_id oluşturulana kadar bekle (kısa)
        ready.wait(timeout=3)
        scan_id = scan_id_holder.get("scan_id")

        return jsonify({
            "status": "started",
            "scan_id": scan_id,
            "message": "Tarama arka planda başlatıldı"
        }), 202

    @app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
    def delete_scan(scan_id):
        """Taramayı sil."""
        db.delete_scan(scan_id)
        return jsonify({"status": "deleted"})

    @app.route("/api/scanners")
    def list_scanners():
        """Mevcut tarayıcı modülleri."""
        scanners = []
        for name, cls in SCANNER_REGISTRY.items():
            scanners.append({
                "name": name,
                "description": cls.description,
                "default": name in DEFAULT_MODULES,
            })
        return jsonify(scanners)

    @app.route("/api/scenarios")
    def list_scenarios():
        """Yüklü YAML senaryolar."""
        scenarios_dir = os.path.join(PROJECT_ROOT, "scenarios_data")
        result = []
        if os.path.isdir(scenarios_dir):
            try:
                import yaml
                for fn in sorted(os.listdir(scenarios_dir)):
                    if fn.endswith((".yaml", ".yml")):
                        path = os.path.join(scenarios_dir, fn)
                        try:
                            with open(path, "r", encoding="utf-8") as f:
                                data = yaml.safe_load(f) or {}
                            result.append({
                                "filename": fn,
                                "id": data.get("id"),
                                "name": data.get("info", {}).get("name"),
                                "author": data.get("info", {}).get("author"),
                                "severity": data.get("info", {}).get("severity"),
                                "description": data.get("info", {}).get("description"),
                            })
                        except Exception:
                            result.append({"filename": fn, "error": "parse hatası"})
            except ImportError:
                pass
        return jsonify(result)

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Sunucu hatası", "detail": str(e)}), 500

    return app


def _render_download_button(scan_id: int) -> str:
    """HTML rapor sayfasına enjekte edilecek 'PDF indir' yüzen düğmesi."""
    return f"""
<div style="position:fixed;top:24px;right:24px;z-index:9999;
            display:flex;gap:8px;font-family:-apple-system,sans-serif;">
  <a href="/api/scans/{scan_id}/report.pdf"
     style="background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);
            color:white;padding:12px 18px;border-radius:10px;
            text-decoration:none;font-weight:600;font-size:14px;
            display:inline-flex;align-items:center;gap:8px;
            box-shadow:0 4px 14px rgba(239,68,68,0.4);
            transition:transform 0.15s;"
     onmouseover="this.style.transform='translateY(-2px)'"
     onmouseout="this.style.transform='translateY(0)'">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
         stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
         stroke-linejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
      <polyline points="7 10 12 15 17 10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
    PDF İndir
  </a>
  <a href="/api/scans/{scan_id}/report.json"
     style="background:rgba(255,255,255,0.95);color:#1e293b;
            padding:12px 18px;border-radius:10px;
            text-decoration:none;font-weight:600;font-size:14px;
            display:inline-flex;align-items:center;gap:8px;
            box-shadow:0 4px 14px rgba(0,0,0,0.15);
            transition:transform 0.15s;border:1px solid #e2e8f0;"
     onmouseover="this.style.transform='translateY(-2px)'"
     onmouseout="this.style.transform='translateY(0)'">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
         stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
         stroke-linejoin="round">
      <polyline points="16 18 22 12 16 6"/>
      <polyline points="8 6 2 12 8 18"/>
    </svg>
    JSON
  </a>
</div>
"""


def _execute_scan(target: str, modules, ready_event=None):
    """Tarama akışını çalıştırır ve raporları üretir."""
    orchestrator = Orchestrator(verbose=False)

    # Scan_id oluşur oluşmaz event'i tetikle (asenkron API için)
    db = get_db()
    scan_id_pre = db.create_scan(target, modules)

    # Orchestrator'a hazır scan_id ile geçmiyoruz, kendi oluşturur — ama
    # asenkron API'nin scan_id'yi hemen dönmesi gerekiyor. Bu yüzden
    # küçük bir trick: create_scan'i biz çağırıyoruz, sonra orchestrator
    # bağımsız çalışıyor.
    #
    # Daha temiz çözüm: orchestrator'a önceden_oluşmuş_id parametresi.
    # Şimdilik basit yol: kendi create_scan'imizi sileriz, orchestrator
    # kendininkini oluştursun.
    db.delete_scan(scan_id_pre)

    if ready_event:
        # Scan_id'yi henüz bilemeyiz ama event'i tetikle
        ready_event.set()

    result = orchestrator.scan(target, modules=modules)

    # Raporları üret
    report_gen = ReportGenerator()
    html_path = report_gen.generate_html(result)
    json_path = report_gen.generate_json(result)
    db.update_report_paths(result.scan_id, html_path=html_path, json_path=json_path)

    # PDF'i de üret (reportlab kuruluysa) — kullanıcı anında indirebilsin
    try:
        report_gen.generate_pdf(result)
    except Exception:
        pass  # reportlab yoksa sessiz geç

    return result


def run(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    """Sunucuyu başlat."""
    app = create_app()
    print(f"\n{'=' * 60}")
    print(f"  🛡️  Sızma Testi Otomasyon Aracı — Web Paneli")
    print(f"      (Siber Savaşçılar Ekibi)")
    print(f"{'=' * 60}")
    print(f"  Adres: http://{host}:{port}")
    print(f"  API  : http://{host}:{port}/api/scans")
    print(f"  Durmak için Ctrl+C\n")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    run()
