#!/usr/bin/env bash
# Rebuild the report PDF from the editable HTML source.
# Edit  Meridian_Portal_Security_Report.src.html  (any text editor), then run:  ./render_report.sh
set -e
cd "$(dirname "$0")"
../.report-venv/bin/python - <<'PY'
from weasyprint import HTML
import os
HTML("Meridian_Portal_Security_Report.src.html", base_url=os.getcwd()).write_pdf(
    "Meridian_Portal_Security_Report.pdf")
print("rebuilt Meridian_Portal_Security_Report.pdf")
PY
