#!/usr/bin/env python3
"""Consolidate CI evidence without exposing raw scanner findings."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import xml.etree.ElementTree as ET

CI_JOBS = ['flake8', 'hadolint', 'wordlists_integrity', 'terraform_validate', 'gitleaks', 'bandit', 'semgrep', 'pip_audit', 'trivy_fs', 'checkov', 'pytest', 'build_image', 'image_functional_test', 'image_scan']
CLOUD_JOBS = ['infra_plan', 'infra_apply', 'publish_ecr', 'deploy_app', 'smoke_test', 'dast_zap']
ROOT = Path(os.environ.get("CI_PROJECT_DIR", "."))
STATUS_LABELS = {
    "success": "Réussi",
    "failed": "Échec",
    "canceled": "Annulé",
    "unknown": "Non confirmé / non exécuté",
}


def read_json(filename):
    try:
        return json.loads((ROOT / filename).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def junit(filename):
    try:
        root = ET.parse(ROOT / filename).getroot()
    except (OSError, ET.ParseError):
        return None
    cases = list(root.iter("testcase"))
    return {
        "tests": len(cases),
        "failures": sum(c.find("failure") is not None for c in cases),
        "errors": sum(c.find("error") is not None for c in cases),
        "skipped": sum(c.find("skipped") is not None for c in cases),
    }


def details(job):
    if job in ("pytest", "checkov"):
        return junit(job + ".xml")
    if job == "gitleaks":
        data = read_json("gitleaks.json")
        return {"findings": len(data)} if isinstance(data, list) else None
    if job in ("bandit", "semgrep"):
        data = read_json(job + ".json")
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            return None
        return {"findings": len(data["results"]), "scanner_errors": len(data.get("errors", []))}
    if job == "pip_audit":
        data = read_json("pip-audit.json")
        deps = data.get("dependencies") if isinstance(data, dict) else data
        if not isinstance(deps, list):
            return None
        return {
            "dependencies": len(deps),
            "vulnerabilities": sum(len(d.get("vulns", [])) for d in deps),
            "skipped_dependencies": sum("skip_reason" in d for d in deps),
        }
    if job == "image_scan":
        data = read_json("trivy-image.json")
        bom = read_json("sbom.cdx.json")
        result = {}
        if isinstance(data, dict) and isinstance(data.get("Results"), list):
            vulns = [v for r in data["Results"] for v in (r.get("Vulnerabilities") or [])]
            counts = Counter(v.get("Severity", "UNKNOWN") for v in vulns)
            result.update({
                "all_severities": dict(sorted(counts.items())),
                "high_critical": counts["HIGH"] + counts["CRITICAL"],
                "high_critical_with_fixed_version": sum(
                    v.get("Severity") in ("HIGH", "CRITICAL")
                    and bool(v.get("FixedVersion")) for v in vulns
                ),
                "unique_vulnerability_ids": len({
                    v["VulnerabilityID"] for v in vulns if v.get("VulnerabilityID")
                }),
            })
        if isinstance(bom, dict) and isinstance(bom.get("components"), list):
            result["sbom_components"] = len(bom["components"])
        return result or None
    if job == "dast_zap":
        data = read_json("zap-report.json")
        if isinstance(data, dict) and isinstance(data.get("site"), list):
            alerts = [a for s in data["site"] for a in (s.get("alerts") or [])]
            return {"alert_groups": len(alerts), "risk_codes": dict(Counter(
                str(a.get("riskcode", "unknown")) for a in alerts
            ))}
    return None


def collect(job):
    try:
        status = (ROOT / "ci-status" / (job + ".txt")).read_text().strip()
    except OSError:
        status = "unknown"
    if status not in STATUS_LABELS:
        status = "unknown"
    return {"job": job, "status": status, "details": details(job)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", choices=("ci", "full"), required=True)
    scope = parser.parse_args().scope
    rows = [collect(j) for j in CI_JOBS + (CLOUD_JOBS if scope == "full" else [])]
    counts = dict(Counter(r["status"] for r in rows))
    summary = {
        "project": os.environ.get("CI_PROJECT_PATH", "PassCheck"),
        "commit": os.environ.get("CI_COMMIT_SHA", "local"),
        "ref": os.environ.get("CI_COMMIT_REF_NAME", "local"),
        "pipeline_id": os.environ.get("CI_PIPELINE_ID", "local"),
        "pipeline_url": os.environ.get("CI_PIPELINE_URL", ""),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "scope": scope,
        "counts": counts,
        "checks": rows,
    }
    output = ROOT / ("ci-report" if scope == "ci" else "deployment-report")
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    title = "PassCheck — Rapport DevSecOps " + ("CI" if scope == "ci" else "CI/CD")
    overview = "".join(
        f"<li>{escape(k)} : {escape(str(summary[k]))}</li>"
        for k in ("project", "commit", "ref", "pipeline_id", "pipeline_url", "generated_utc")
    )
    totals = " · ".join(f"{STATUS_LABELS[k]} : {counts.get(k, 0)}" for k in STATUS_LABELS)
    table_rows = []
    for row in rows:
        detail = row["details"]
        description = json.dumps(detail, ensure_ascii=False) if detail is not None else "Aucun rapport structuré disponible"
        status = row["status"]
        table_rows.append(
            f'<tr><td>{escape(row["job"])}</td><td class="{status}">'
            f'{STATUS_LABELS[status]}</td><td>{escape(description)}</td></tr>'
        )
    note = (
        "Ce rapport couvre les contrôles avant déploiement. Les étapes AWS et DAST "
        "sont hors périmètre de ce rapport." if scope == "ci" else
        "Ce rapport couvre les contrôles CI et les étapes de déploiement, hors destruction."
    )
    html = f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>{title}</title>
<style>
body{{font:16px system-ui,sans-serif;color:#172638;background:#f4f6f9;margin:0}}
main{{max-width:1080px;margin:32px auto;padding:28px;background:white}}
h1{{color:#173e60}} table{{border-collapse:collapse;width:100%;font-size:14px}}
td,th{{padding:12px;text-align:left;border-bottom:1px solid #ddd;overflow-wrap:anywhere}}
th{{background:#173e60;color:white}} .success{{color:#08643b}} .failed{{color:#b42318}}
.unknown,.canceled{{color:#805400}} .summary{{padding:14px;background:#edf2f7;font-weight:bold}}
@media print{{main{{margin:0;padding:0}}body{{background:white}}}}
</style></head><body><main>
<h1>{title}</h1><ul>{overview}</ul><p>{escape(note)}</p>
<p class="summary">{escape(totals)}</p>
<table><thead><tr><th>Contrôle</th><th>Statut observé</th><th>Indicateurs</th></tr></thead>
<tbody>{"".join(table_rows)}</tbody></table>
<h2>Limites et interprétation</h2>
<p>Les statuts proviennent de CI_JOB_STATUS enregistré dans after_script, avant
le transfert des artefacts. Une preuve absente signifie un résultat non confirmé,
jamais un succès. Consulter GitLab pour le statut définitif des jobs.</p>
<p>Les occurrences Trivy concernent les couples paquet/vulnérabilité. Le contrôle
bloquant ignore les vulnérabilités non corrigibles selon la base du scanner.
Le rapport complet conserve les autres occurrences. Le SBOM est un inventaire,
pas une preuve d'absence de vulnérabilités. Aucun secret ni détail de finding
n'est reproduit ici.</p></main></body></html>"""
    (output / "report.html").write_text(html, encoding="utf-8")
    print(totals)
    print(f"Rapport : {output / 'report.html'}")


if __name__ == "__main__":
    main()
