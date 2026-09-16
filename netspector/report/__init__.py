"""Report generation package for NetSpector Pro."""

from netspector.report.text import render_text_report
from netspector.report.json_rep import export_json_report
from netspector.report.html_rep import start_web_dashboard, render_static_html

__all__ = ["render_text_report", "export_json_report", "start_web_dashboard", "render_static_html"]
