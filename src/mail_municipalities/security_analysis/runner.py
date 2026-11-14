"""Security scan pipeline: orchestrate Docker scanner/evaluator and write output JSON."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any
import pandas as pd
from loguru import logger
import csv

from .defaults import DEFAULTS
from .models import MunicipalitySecurity
from.models_result_kotlin import *

# Path to the security_test directory (sibling of mail_municipalities under src/)
_SECURITY_TEST_DIR = Path(__file__).resolve().parents[2] / "security_test"


# ── Docker helpers ─────────────────────────────────────────────────────


def find_docker_compose() -> list[str]:
    """Return the docker compose command as a list of args."""
    if shutil.which("docker"):
        result = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    msg = "Neither 'docker compose' (v2) nor 'docker-compose' (v1) found. Install Docker first."
    raise RuntimeError(msg)


def ensure_env(security_test_dir: Path) -> None:
    """Create a .env file with defaults if one doesn't exist."""
    env_path = security_test_dir / ".env"
    if env_path.exists():
        logger.debug("Using existing .env at {}", env_path)
        return
    lines = [f"{k}={v}" for k, v in DEFAULTS.items()]
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Generated default .env at {}", env_path)


def _clear_dir(directory: Path) -> None:
    """Remove all files in a directory (keep the directory and .gitkeep)."""
    if not directory.exists():
        return
    for f in directory.iterdir():
        if f.is_file() and f.name != ".gitkeep":
            f.unlink()


# ── Input preparation ──────────────────────────────────────────────────


def prepare_scanner_input(domains_path: Path, scanner_input_dir: Path, cc: str) -> Path:
    """Read domains JSON and write scanner input in checked_emails format.

    Returns the path to the written scanner input file.
    """
    with open(domains_path, encoding="utf-8") as f:
        data = json.load(f)

    domains: set[str] = set()
    for muni in data["municipalities"]:
        for email_domain in muni.get("emails", []):
            if email_domain:
                domains.add(email_domain)

    checked_emails = sorted(f"info@{d}" for d in domains)
    logger.info("Prepared {} unique domains for scanning from {}", len(checked_emails), domains_path.name)

    _clear_dir(scanner_input_dir)
    scanner_input_dir.mkdir(parents=True, exist_ok=True)
    out_path = scanner_input_dir / f"{cc}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"checked_emails": checked_emails}, f, ensure_ascii=False, indent=2)

    return out_path


# ── Docker execution ───────────────────────────────────────────────────


def _run_container(compose_cmd: list[str], service: str, cwd: Path, verbose: bool) -> None:
    """Run a docker compose service, streaming output to the logger."""
    # Abwärtskompatibilität und autmatische mitstarten des lokalen rek. dns resolvers
    cmd = [*compose_cmd, "up", "--build", "--exit-code-from", service, service, "unbound"]
    logger.info("Running: {} (cwd={})", " ".join(cmd), cwd)

    with subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    ) as proc:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            if verbose:
                logger.info("[{}] {}", service, line)
            else:
                # Always surface key progress lines from the scanner
                lower = line.lower()
                if any(
                    kw in lower
                    for kw in ("starting", "finished", "loaded", "using", "resolving", "error", "warn", "failed")
                ):
                    logger.info("[{}] {}", service, line)

    if proc.returncode != 0:
        msg = f"Docker service '{service}' exited with code {proc.returncode}"
        raise RuntimeError(msg)


def run_docker_scanner(security_test_dir: Path, compose_cmd: list[str], verbose: bool) -> None:
    """Run the scanner Docker container."""
    _run_container(compose_cmd, "scanmuni", security_test_dir, verbose)


def run_docker_evaluator(security_test_dir: Path, compose_cmd: list[str], cc: str, verbose: bool) -> Path:
    """Move scanner results to evaluator input, run evaluator, return result path."""
    scanner_result_dir = security_test_dir / "scanner" / "scanner-result"
    evaluator_input_dir = security_test_dir / "evaluator" / "evaluator-input"
    evaluator_result_dir = security_test_dir / "evaluator" / "evaluator-result"

    _clear_dir(evaluator_input_dir)
    _clear_dir(evaluator_result_dir)

    # Move scanner results to evaluator input
    for f in scanner_result_dir.iterdir():
        if f.is_file() and f.suffix == ".json":
            shutil.move(str(f), evaluator_input_dir / f.name)

    _run_container(compose_cmd, "evalmuni", security_test_dir, verbose)

    result_path = evaluator_result_dir # / f"{cc}_domainInfoList.json"
    if not result_path.exists():
        msg = f"Expected evaluator output not found: {result_path}"
        raise FileNotFoundError(msg)
    return result_path


# ── Output transformation ─────────────────────────────────────────────


def build_domain_security(json_data: Any) -> dict[str, domainInfo]:
    """Übernimmt nach einer Typprüfung 
    """
    result: dict[str, domainInfo] = {}

    if not isinstance(json_data, list):
        logger.error("Die übergebenen Daten sind keine Liste. Abbruch.")
        return result

    # 2. Über die raw JSON-Dictionaries iterieren
    for row_dict in json_data:
        try:
            # Das eigentliche Pydantic-Objekt erstellen (Hier findet die Validierung statt!)
            validiertes_objekt = domainInfo(**row_dict)
            result[validiertes_objekt.domainname] = validiertes_objekt
            
        except Exception as e:
            logger.error(f"Unerwarteter Fehler beim Verarbeiten eines Eintrags: {e}")

    return result


def _load_security_overrides(cc: str) -> dict[str, dict[str, Any]]:
    """Load security scan overrides from ``data/{cc}/security_overrides.json``.

    Returns dict keyed by municipality code.  Returns empty dict if the file does not exist.
    """
    path = Path("data") / cc / "security_overrides.json"
    if not path.exists():
        return {}

    with open(path, encoding="utf-8") as f:
        raw: dict[str, Any] = json.load(f)

    overrides: dict[str, dict[str, Any]] = {}
    for code, entry in raw.items():
        if "source" not in entry:
            logger.warning("security override {}: missing 'source' field — skipped", code)
            continue
        overrides[code] = entry

    logger.info("Loaded {} security overrides from {}", len(overrides), path)
    return overrides



def clean_column_names_two_labels(columns):
    """
    Behält die letzten zwei Labels eines verschachtelten JSON-Pfads bei 
    und verbindet sie mit einem Unterstrich (z.B. spfGeneralData_dnsLookups).
    """
    new_cols = []
    for col in columns:
        if col == 'domainname':
            new_cols.append(col)
            continue
        
        # Am Punkt aufteilen
        parts = col.split('.')
        
        # Wenn der Pfad mindestens 2 Ebenen hat, nimm die letzten beiden
        if len(parts) >= 2:
            new_name = f"{parts[-2]}_{parts[-1]}"
        else:
            # Falls es (warum auch immer) nur eine Ebene gibt
            new_name = parts[-1]
            
        new_cols.append(new_name)
    return new_cols

def drop_intermediate_columns(df):
    """
    Erkennt und entfernt überflüssige Eltern-Knoten-Spalten die durch 
    'null'-Werte am Anfang des JSONs fälschlicherweise behalten wurden.
    """
    cols = df.columns.tolist()
    cols_to_drop = []
    
    for col in cols:
        # Prüfen, ob es irgendeine andere Spalte gibt, welche ein Kind dieser Spalte ist
        if any(other.startswith(col + '.') for other in cols):
            cols_to_drop.append(col)
            
    return df.drop(columns=cols_to_drop)


def clean_cell_values(df: pd.DataFrame) -> pd.DataFrame:
    """Wandelt Listen und Dictionaries in saubere Strings um."""
    for col in df.columns:
        df[col] = df[col].apply(
            lambda x: ', '.join(map(str, x)) if isinstance(x, list)
            else (json.dumps(x, ensure_ascii=False) if isinstance(x, dict) else x)
        )
    return df

def extract_1_to_1_table(df, prefix, filename):
    metadata_cols = ['domainname', 'code', 'name', 'region', 'tier_id']
    cols = metadata_cols + [c for c in df.columns if str(c).startswith(f"{prefix}.")]
    df_subset = df[cols].copy()
    
    df_subset.columns = clean_column_names_two_labels(df_subset.columns)
    df_subset = clean_cell_values(df_subset)
    
    # Excel-kompatibler CSV-Export mit BOM und vollständigem Quoting
    df_subset.to_csv(
        f'{filename}.csv', 
        index=False, 
        sep=';', 
        decimal=',', 
        encoding='utf-8-sig', 
        quoting=csv.QUOTE_ALL
    )
    df_subset.to_excel(f'{filename}.xlsx', index=False, engine="openpyxl")
    logger.info(f"Gespeichert: {filename} ({len(df_subset)} Zeilen)")


def extract_1_to_n_table(data, list_key, filename):
    try:
        metadata_cols = ['code', 'name', 'region', 'tier_id']
        df_list = pd.json_normalize(
            data['municipalities'], 
            record_path=list_key, 
            meta=metadata_cols,
            errors='ignore'
        )
        if df_list.empty:
            return

        df_list = drop_intermediate_columns(df_list)
        df_list = df_list.convert_dtypes() 
        cols = metadata_cols + [c for c in df_list.columns if c not in metadata_cols]
        df_list = df_list[cols]
        df_list.columns = clean_column_names_two_labels(df_list.columns)
        df_list = clean_cell_values(df_list)

        df_list.to_csv(
            f'{filename}.csv', 
            index=False, 
            sep=';', 
            decimal=',', 
            encoding='utf-8-sig', 
            quoting=csv.QUOTE_ALL
        )

        df_list.to_excel(f'{filename}.xlsx', index=False, engine="openpyxl")


        logger.info(f"Gespeichert: {filename} ({len(df_list)} Zeilen)")
    except KeyError:
        logger.info(f"Keine Daten für {list_key} gefunden.")




def extract_1_to_1_table_rpt(df, prefix, filename):
    #metadata_cols = ['domainname', 'code', 'name', 'region', 'tier_id']

    
    #cols = metadata_cols + [c for c in df.columns if str(c).startswith(f"{prefix}.")]
    cols = [c for c in df.columns if str(c).startswith(f"{prefix}.")]


    df_subset = df[cols].copy()
    
    df_subset.columns = clean_column_names_two_labels(df_subset.columns)
    df_subset = clean_cell_values(df_subset)
    
    # Excel-kompatibler CSV-Export mit BOM und vollständigem Quoting
    df_subset.to_csv(
        f'{filename}.csv', 
        index=False, 
        sep=';', 
        decimal=',', 
        encoding='utf-8-sig', 
        quoting=csv.QUOTE_ALL
    )
    df_subset.to_excel(f'{filename}.xlsx', index=False, engine="openpyxl")
    logger.info(f"Gespeichert: {filename} ({len(df_subset)} Zeilen)")



def extract_1_to_n_table_rpt(data, list_key, filename):
    try:
        #metadata_cols = ['code', 'name', 'region', 'tier_id']

        df_list = pd.json_normalize(
            data, 
            record_path=list_key, 
            #meta=metadata_cols,
            errors='ignore'
        )

        if df_list.empty:
            return

        df_list = drop_intermediate_columns(df_list)
        df_list = df_list.convert_dtypes() 


        #cols = metadata_cols + [c for c in df_list.columns if c not in metadata_cols]
        cols = [c for c in df_list.columns]


        df_list = df_list[cols]
        df_list.columns = clean_column_names_two_labels(df_list.columns)
        df_list = clean_cell_values(df_list)

        df_list.to_csv(
            f'{filename}.csv', 
            index=False, 
            sep=';', 
            decimal=',', 
            encoding='utf-8-sig', 
            quoting=csv.QUOTE_ALL
        )

        df_list.to_excel(f'{filename}.xlsx', index=False, engine="openpyxl")
        logger.info(f"Gespeichert: {filename} ({len(df_list)} Zeilen)")
    except KeyError:
        logger.info(f"Keine Daten für {list_key} gefubden")






def extract_to_csv(security_json, cc):

    # Ordnerpfad festlegen

    # Datei einlesen
    with open(security_json, encoding="utf-8") as f:
        json_output_daten = json.load(f)

    # Zielordner vorab anlegen (falls noch nicht vorhanden)
    output_ordner = Path(f'./output/security/data/{cc}')
    output_ordner.mkdir(parents=True, exist_ok=True)

    # Daten normalisieren und bereinigen
    df_main = pd.json_normalize(json_output_daten['municipalities'])
    df_main = drop_intermediate_columns(df_main)
    df_main = df_main.convert_dtypes()


    # AUSFÜHRUNG & EXPORT

    logger.info(f"Starte Datenexport für {security_json}...")

    extract_1_to_1_table(df_main, 'aggDomainAntiSpoofing', output_ordner / 'antispoofing_data')
    extract_1_to_1_table(df_main, 'aggDomainDataTransport', output_ordner / 'transport_data')

    extract_1_to_n_table(json_output_daten, 'mxData', output_ordner / 'mx_data')
    extract_1_to_n_table(json_output_daten, 'mtaStsErrorList', output_ordner / 'mta_sts_error')
    extract_1_to_n_table(json_output_daten, 'dmarcReportDomain', output_ordner / 'dmarc_report_domain')
    extract_1_to_n_table(json_output_daten, 'externalDependencyList', output_ordner / 'external_dependencies.')


def extract_to_csv_rpt(security_json,cc):

    # Datei einlesen
    with open(security_json, encoding="utf-8") as f:
        json_output_daten = json.load(f)

    # Zielordner vorab anlegen falls noch nicht vorhanden
    output_ordner = Path(f'./output/security/dmarc_rpt_data/{cc}')
    output_ordner.mkdir(parents=True, exist_ok=True)

    # Daten normalisieren und bereinigen
    df_main = pd.json_normalize(json_output_daten)
    df_main = drop_intermediate_columns(df_main)
    df_main = df_main.convert_dtypes()

    
    logger.info(f"Starte Datenexport für {security_json}")

    extract_1_to_1_table_rpt(df_main, 'aggDomainAntiSpoofing', output_ordner / 'antispoofing_data')
    extract_1_to_1_table_rpt(df_main, 'aggDomainDataTransport', output_ordner / 'transport_data')

    extract_1_to_n_table_rpt(json_output_daten, 'mxData', output_ordner / 'mx_data')
    extract_1_to_n_table_rpt(json_output_daten, 'mtaStsErrorList', output_ordner / 'mta_sts_error')
    extract_1_to_n_table_rpt(json_output_daten, 'dmarcReportDomain', output_ordner / 'dmarc_report_domain')
    extract_1_to_n_table_rpt(json_output_daten, 'externalDependencyList', output_ordner / 'external_dependencies.')






def _apply_security_overrides(
    municipalities: list[MunicipalitySecurity],
    overrides: dict[str, dict[str, Any]],
) -> int:
    """Apply security overrides to municipality results.  Returns count applied."""
    by_code = {m.code: m for m in municipalities}
    applied = 0
    for code, override in overrides.items():
        if code not in by_code:
            logger.warning("security override for {} but municipality not in results", code)
            continue

        muni = by_code[code]

        # Merge DSS fields
        if "dss" in override and muni.dss is not None:
            for field, value in override["dss"].items():
                setattr(muni.dss, field, value)

        # Merge DANE fields
        if "dane" in override and muni.dane is not None:
            for field, value in override["dane"].items():
                setattr(muni.dane, field, value)

        muni.scan_valid = True
        muni.override = {"source": override["source"]}
        applied += 1

    return applied


def build_output(domains_path: Path, domain_security: dict[str, domainInfo], cc: str) -> SecurityOutput:
    """Map security data back to municipalities and build the output envelope."""
    with open(domains_path, encoding="utf-8") as f:
        data = json.load(f)

    commit = (
        subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        or None
    )

    domain_security = domain_security or {}

    municipalities: list[domainInfo] = []
    for muni in data.get("municipalities", []):
        emails = muni.get("emails", [])
        domain = emails[0] if emails else ""
        sec = domain_security.get(domain, None)
        
        if sec is not None:
            # Bei Pydantic-Objekten Werte mit Punkt-Notation (!) zuweisen
            
            sec = sec.model_copy(deep=True)

            sec.code = muni.get("code")
            sec.name = muni.get("name")
            sec.region = muni.get("region")

            # tier_id darf null sein
            sec.tier_id = muni.get("tier_id")
            municipalities.append(sec)

    return SecurityOutput(
            generated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            commit=commit,
            total=len(municipalities),
            municipalities=municipalities,
        )

    # Apply security overrides
    #security_overrides = _load_security_overrides(cc)
    #if security_overrides:
    #    overrides_applied = _apply_security_overrides(municipalities, security_overrides)
    #    logger.info("Security overrides: {} available, {} applied", len(security_overrides), overrides_applied)

    # Aggregate counts
    #scanned = sum(1 for m in municipalities if m.scan_valid)
    #counts = {
    #    "scanned": scanned,
    #    "dane_supported": sum(1 for m in municipalities if m.dane and m.dane.supported),
    #    "spf": sum(1 for m in municipalities if m.dss and m.dss.has_spf),
    #    "good_spf": sum(1 for m in municipalities if m.dss and m.dss.has_good_spf),
    #    "dmarc": sum(1 for m in municipalities if m.dss and m.dss.has_dmarc),
    #    "good_dmarc": sum(1 for m in municipalities if m.dss and m.dss.has_good_dmarc),
    #    "dkim": sum(1 for m in municipalities if m.dss and m.dss.has_dkim),
    #}

    


# ── Top-level orchestrator ─────────────────────────────────────────────


def run(domains_path: Path, output_path: Path, *, cc: str, verbose: bool = False) -> None:
    """Run the full security scan pipeline for a country."""
    security_test_dir = _SECURITY_TEST_DIR
    if not security_test_dir.exists():
        msg = f"Security test directory not found: {security_test_dir}"
        raise FileNotFoundError(msg)

    compose_cmd = find_docker_compose()
    ensure_env(security_test_dir)

    scanner_input_dir = security_test_dir / "scanner" / "scanner-input"
    scanner_result_dir = security_test_dir / "scanner" / "scanner-result"

    # Clean up from previous runs
    _clear_dir(scanner_result_dir)

    # Phase 1: Prepare input
    logger.info("Phase 1: Preparing scanner input for {}", cc)
    prepare_scanner_input(domains_path, scanner_input_dir, cc)

    # Phase 2: Run scanner
    logger.info("Phase 2: Running security scanner (Docker)")
    t0 = time.monotonic()
    run_docker_scanner(security_test_dir, compose_cmd, verbose)
    logger.info("Scanner completed in {:.1f}s", time.monotonic() - t0)

    # Phase 3: Run evaluator
    logger.info("Phase 3: Running evaluator (Docker)")
    t1 = time.monotonic()
    evaluator_result = run_docker_evaluator(security_test_dir, compose_cmd, cc, verbose)
    logger.info("Evaluator completed in {:.1f}s", time.monotonic() - t1)





    

    # Phase 4: Transform output
    logger.info("Phase 4: Building output")
    eval_path_sec = evaluator_result / f"{cc}_domainInfoList.json"
    with open( eval_path_sec, encoding="utf-8") as f:
        domain_info_list = json.load(f)


    
    
    domain_security = build_domain_security(domain_info_list)
    output = build_output(domains_path, domain_security, cc)

    # Write output
    #json_output_daten = output.municipalities[m.model_dump() for m in municipalities]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output.model_dump(), f, ensure_ascii=False, indent=2, separators=(",", ":"))

    size_kb = output_path.stat().st_size / 1024
    logger.info("Wrote {} ({:.0f} KB)", output_path, size_kb)


    # Neu in PHASE 4: Erstelle CSV-Dateien
    eval_path_rpt = evaluator_result / f"ext{cc}_domainInfoList.json"
    extract_to_csv(output_path, cc)
    extract_to_csv_rpt(eval_path_rpt,cc)


    logger.info("Wrote {} ({:.0f} KB)", output_path, size_kb)
    logger.info(
        "--- Security scan: {} municipalities ---",
        output.total
    )
