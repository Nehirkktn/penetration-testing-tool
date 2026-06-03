#!/usr/bin/env python3
"""
Sızma Testi Otomasyon Aracı — CLI Arayüzü
==========================================

Komut satırından tarama başlatmak için ana giriş noktası.

Kullanım:
    python -m siber_savascilar.cli <hedef-url>
    python -m siber_savascilar.cli <hedef-url> --modules sqli xss
    python -m siber_savascilar.cli <hedef-url> --no-html --no-pdf
"""

import argparse
import sys

from .orchestrator import Orchestrator, DEFAULT_MODULES
from .reporting import ReportGenerator
from .scanners import SCANNER_REGISTRY
from .core.database import get_db


def main():
    parser = argparse.ArgumentParser(
        prog="sizma-testi",
        description="Sızma Testi Otomasyon Aracı — Siber Savaşçılar Ekibi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  siber-savascilar http://testphp.vulnweb.com
  siber-savascilar http://example.com --modules sqli xss misconfig
  siber-savascilar http://example.com --quick
  siber-savascilar --list-scans
"""
    )

    parser.add_argument("target", nargs="?", help="Taranacak URL veya host")
    parser.add_argument(
        "--modules", "-m",
        nargs="+",
        choices=list(SCANNER_REGISTRY.keys()),
        help=f"Çalıştırılacak modüller (varsayılan: {', '.join(DEFAULT_MODULES)})"
    )
    parser.add_argument("--quick", "-q", action="store_true",
                        help="Hızlı tarama (sadece sqli, xss, misconfig)")
    parser.add_argument("--no-html", action="store_true", help="HTML rapor üretme")
    parser.add_argument("--no-json", action="store_true", help="JSON rapor üretme")
    parser.add_argument("--pdf", action="store_true",
                        help="PDF rapor da üret (reportlab gerekir)")
    parser.add_argument("--quiet", action="store_true", help="Sessiz mod")
    parser.add_argument("--abort-if-unreachable", action="store_true",
                        help="Hedef ulaşılamazsa hiç tarama yapmadan çık")
    parser.add_argument("--list-scans", action="store_true",
                        help="Önceki taramaları listele")

    args = parser.parse_args()

    # Eski taramaları listele
    if args.list_scans:
        list_scans()
        return 0

    if not args.target:
        parser.print_help()
        return 1

    # Modülleri belirle
    if args.quick:
        modules = ["sqli", "xss", "misconfig"]
    else:
        modules = args.modules or DEFAULT_MODULES

    # Tarama başlat
    orchestrator = Orchestrator(verbose=not args.quiet)

    # Ulaşılamazsa erken çıkış istendiyse kontrol et
    if args.abort_if_unreachable:
        from .core.validators import URLValidator
        target_norm = URLValidator.normalize(args.target)
        reachable, msg = orchestrator._check_reachable(target_norm)
        if not reachable:
            print(f"❌ Hedef ulaşılamaz: {msg}")
            print(f"   --abort-if-unreachable aktif, tarama yapılmadan çıkılıyor.")
            return 2

    result = orchestrator.scan(args.target, modules=modules)

    # Raporları üret
    report_gen = ReportGenerator()
    db = get_db()

    if not args.no_html:
        html_path = report_gen.generate_html(result)
        db.update_report_paths(result.scan_id, html_path=html_path)
        print(f"📄 HTML rapor : {html_path}")

    if not args.no_json:
        json_path = report_gen.generate_json(result)
        db.update_report_paths(result.scan_id, json_path=json_path)
        print(f"📄 JSON rapor : {json_path}")

    if args.pdf:
        pdf_path = report_gen.generate_pdf(result)
        if pdf_path:
            print(f"📄 PDF rapor  : {pdf_path}")
        else:
            print("⚠️  PDF için reportlab kurulu olmalı: pip install reportlab")

    return 0


def list_scans():
    db = get_db()
    scans = db.list_scans(limit=20)
    if not scans:
        print("Henüz hiç tarama yapılmamış.")
        return

    print(f"\n{'ID':<6}{'HEDEF':<40}{'DURUM':<14}{'ZAFİYET':<10}{'TARİH':<22}")
    print("─" * 95)
    for s in scans:
        target = (s["target_url"] or "")[:38]
        status = s["status"] or "-"
        vc = s["vuln_count"]
        date = (s["started_at"] or "")[:19]
        print(f"{s['id']:<6}{target:<40}{status:<14}{vc:<10}{date:<22}")
    print()


if __name__ == "__main__":
    sys.exit(main())
