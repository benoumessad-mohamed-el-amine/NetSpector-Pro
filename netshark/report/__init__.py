"""Report generation package for NetShark Pro."""

from netshark.report.text import render_text_report
from netshark.report.json_rep import export_json_report
from netshark.report.html_rep import start_web_dashboard, render_static_html
from netshark.report.history import HistoryManager

__all__ = [
    "render_text_report",
    "export_json_report",
    "start_web_dashboard",
    "render_static_html",
    "HistoryManager",
]
