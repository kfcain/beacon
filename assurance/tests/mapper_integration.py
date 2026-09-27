"""Run with the reviewed grc-pdf-mapper installed; no network mapping is requested."""
import json
import subprocess
import tempfile
from pathlib import Path
from grc_pdf_mapper.pipeline import analyze_document

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='beacon-mapper-integration-') as directory:
    source = Path(directory) / 'policy.md'
    source.write_text('# Access control\n\nAdministrators must use multi-factor authentication for privileged access.\n\nAccess reviews shall occur quarterly.\n')
    report = analyze_document(source, doc_id='pol-integration', offline=True, commit=False, alert_on_change=False)
    output = Path(directory) / 'report.json'
    output.write_text(report.model_dump_json())
    subprocess.run(['node', str(root / 'tests/mapper.integration.mjs'), str(output)], cwd=root, check=True)
    print(json.dumps({'engine': report.ingest.engine, 'statements': len(report.statements), 'candidate_mappings': sum(len(s.mappings) for s in report.statements)}))
