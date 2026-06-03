"""
Özelleştirilebilir YAML Senaryo Motoru
========================================

Muhammed Baki Başbay'ın motor/ozel_tarama_motoru.py ve senaryo_okuyucu.py
modüllerinden geliştirilmiş versiyondur. Nuclei referanslı YAML şablon mimarisi.

Format örneği (scenarios_data/ornek.yaml):
    id: my-test
    info:
      name: "Test adı"
      author: "yazar"
      severity: "Medium"
      description: "Ne yapıyor"
    requests:
      - method: GET
        path:
          - "{{target_url}}/admin"
        matchers:
          - type: status
            status: [200]
          - type: word
            words: ["Welcome admin"]
"""

import os
import requests
from typing import List, Dict, Any
import glob

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from .base import BaseScanner
from ..core.models import Vulnerability, Severity, VulnType


class ScenarioScanner(BaseScanner):
    """YAML şablonlarını çalıştıran tarayıcı."""

    name = "scenario_scanner"
    description = "YAML tabanlı özelleştirilebilir senaryo çalıştırıcı"

    def __init__(self, scenarios_dir: str = None, timeout: int = 10,
                 verbose: bool = True):
        super().__init__(timeout=timeout, verbose=verbose)
        if scenarios_dir is None:
            project_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            scenarios_dir = os.path.join(project_root, "scenarios_data")
        self.scenarios_dir = scenarios_dir

    def scan(self, target: str) -> List[Vulnerability]:
        if not HAS_YAML:
            self.log("PyYAML kurulu değil, senaryo motoru pas geçildi", "warning")
            return []

        self.log(f"Senaryo taraması başlıyor: {target}")
        vulns = []

        scenarios = self._load_scenarios()
        self.log(f"  {len(scenarios)} senaryo yüklendi")

        for scenario_path, scenario in scenarios:
            try:
                found = self._run_scenario(scenario, target, scenario_path)
                vulns.extend(found)
            except Exception as e:
                self.log(f"  Senaryo hatası ({scenario_path}): {e}", "warning")

        return vulns

    def _load_scenarios(self) -> List[tuple]:
        """scenarios_dir altındaki tüm .yaml dosyalarını yükler."""
        if not os.path.isdir(self.scenarios_dir):
            return []

        scenarios = []
        for path in glob.glob(os.path.join(self.scenarios_dir, "*.yaml")) + \
                    glob.glob(os.path.join(self.scenarios_dir, "*.yml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "requests" in data:
                        scenarios.append((path, data))
            except yaml.YAMLError as e:
                self.log(f"  YAML parse hatası: {path}: {e}", "warning")
        return scenarios

    def _run_scenario(self, scenario: Dict[str, Any], target: str,
                      source: str) -> List[Vulnerability]:
        info = scenario.get("info", {})
        scenario_name = info.get("name", scenario.get("id", "unnamed"))
        severity_raw = info.get("severity", "Medium").capitalize()
        severity = severity_raw if Severity.is_valid(severity_raw) else Severity.MEDIUM

        vulns = []

        for req in scenario.get("requests", []):
            method = req.get("method", "GET").upper()
            paths = req.get("path", [])
            matchers = req.get("matchers", [])
            matcher_condition = req.get("matchers-condition", "and")

            for path_template in paths:
                full_url = path_template.replace("{{target_url}}",
                                                 target.rstrip("/"))

                try:
                    response = requests.request(
                        method, full_url, timeout=self.timeout, verify=False
                    )
                except requests.RequestException as e:
                    self.log(f"    İstek hatası: {full_url}: {e}", "warning")
                    continue

                # Tüm matcher'ları değerlendir
                results = [self._evaluate_matcher(m, response) for m in matchers]

                if matcher_condition == "and":
                    match = all(results) and len(results) > 0
                else:  # or
                    match = any(results)

                if match:
                    self.log(f"    [!] Senaryo eşleşti: {scenario_name} → {full_url}")
                    vulns.append(Vulnerability(
                        vuln_type=VulnType.CUSTOM_SCENARIO,
                        severity=severity,
                        target=full_url,
                        description=f"Senaryo eşleşti: {scenario_name}. "
                                    f"{info.get('description', '')}",
                        evidence=f"Senaryo: {os.path.basename(source)} | "
                                 f"Status: {response.status_code}",
                        cwe=info.get("cwe", ""),
                        remediation=info.get("remediation",
                                             "Senaryonun referans aldığı zafiyet "
                                             "için ilgili dokümantasyona bakın."),
                        details={
                            "scenario_id": scenario.get("id"),
                            "scenario_file": os.path.basename(source),
                            "author": info.get("author"),
                            "method": method,
                        },
                    ))

        return vulns

    def _evaluate_matcher(self, matcher: Dict[str, Any], response) -> bool:
        """Bir matcher'ı response üzerinde değerlendirir."""
        mtype = matcher.get("type")

        if mtype == "status":
            expected = matcher.get("status", [])
            return response.status_code in expected

        if mtype == "word":
            words = matcher.get("words", [])
            condition = matcher.get("condition", "or")
            text = response.text
            if condition == "and":
                return all(w in text for w in words)
            return any(w in text for w in words)

        if mtype == "regex":
            import re
            patterns = matcher.get("regex", [])
            return any(re.search(p, response.text) for p in patterns)

        if mtype == "header":
            headers = matcher.get("headers", {})
            return all(response.headers.get(k) == v for k, v in headers.items())

        # Bilinmeyen matcher → False
        return False
