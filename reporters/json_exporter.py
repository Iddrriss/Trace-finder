"""JSON report generation for SIEM and automated ingestion."""

import json
from pathlib import Path
from datetime import datetime, timezone
from reporters.console import get_local_timezone_name


def generate_unique_json_filename(base_name='tracefinder_report'):
    """Generate timestamped JSON filename."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{base_name}_{timestamp}.json"


def export_to_json(findings, triage_window=None, output_file=None, use_timestamp=True):
    """Export findings and scan metadata to a structured JSON document."""
    if not findings:
        print("[!] No findings to export to JSON")
        return None

    try:
        if output_file is None:
            filename = generate_unique_json_filename()
        elif use_timestamp:
            base_name = Path(output_file).stem
            filename = generate_unique_json_filename(base_name)
        else:
            filename = output_file if output_file.endswith('.json') else f"{output_file}.json"

        json_path = Path.cwd() / filename
        local_tz = get_local_timezone_name()

        type_counts = {}
        source_counts = {}
        for finding in findings:
            art_type = finding.get('artifact_type', 'Unknown')
            src = finding.get('source', 'Unknown')
            type_counts[art_type] = type_counts.get(art_type, 0) + 1
            source_counts[src] = source_counts.get(src, 0) + 1

        serialized_findings = []
        for finding in findings:
            utc_dt = finding.get('timestamp_dt')
            local_str = "Conversion Error"
            if isinstance(utc_dt, datetime):
                try:
                    local_dt = utc_dt.astimezone()
                    local_str = local_dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass

            serialized_findings.append({
                'timestamp_utc': finding.get('timestamp'),
                'timestamp_local': local_str,
                'artifact_type': finding.get('artifact_type'),
                'source': finding.get('source'),
                'description': finding.get('description'),
                'details': finding.get('details')
            })

        report_data = {
            'metadata': {
                'tool': 'TraceFinder',
                'version': '2.0',
                'report_generated_utc': datetime.now(timezone.utc).isoformat(),
                'local_timezone': local_tz,
                'total_findings': len(findings),
                'triage_window': triage_window.get_window_info() if triage_window else None
            },
            'statistics': {
                'by_artifact_type': type_counts,
                'by_source': source_counts
            },
            'findings': serialized_findings
        }

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        return str(json_path)

    except Exception as e:
        print(f"[!] Error exporting to JSON: {e}")
        return None
