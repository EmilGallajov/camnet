"""PDF report generation via a user-editable Jinja2 HTML template + WeasyPrint.

Edit templates/report.html.j2 to fully restyle the report (plain HTML/CSS).
"""
import os
from datetime import datetime

from jinja2 import FileSystemLoader, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
TOPO_DIR = os.environ.get("TOPO_DIR", "/app/topologies")
DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
DEFAULT_TPL = os.path.join(TEMPLATE_DIR, "report.html.j2")
USER_TPL = os.path.join(DATA_DIR, "report.html.j2")

# Sandboxed: the report template is user-editable, so block SSTI escapes
# (access to __class__, __globals__, etc.) when rendering it.
_env = SandboxedEnvironment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "j2"]),
)


# ---- user-editable template management ----------------------------------
def has_custom_template():
    return os.path.exists(USER_TPL)


def get_template_text():
    path = USER_TPL if has_custom_template() else DEFAULT_TPL
    with open(path, encoding="utf-8") as f:
        return f.read()


def save_template_text(text):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USER_TPL, "w", encoding="utf-8") as f:
        f.write(text)


def reset_template():
    if has_custom_template():
        os.remove(USER_TPL)


def validate_template(text):
    """Raise if the template has Jinja2 syntax errors."""
    _env.from_string(text)


def _build_context(analysis, threats, devices):
    asserts = []
    for k, v in analysis.get("default_asserts", {}).items():
        if k == "_summary" or not isinstance(v, dict):
            continue
        passed = v.get("passed")
        status = "—" if passed is None else ("PASS" if passed else "FAIL")
        asserts.append({"name": k, "count": v.get("count", 0), "status": status})

    return {
        "report": {
            "generated": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "source": analysis.get("config_source", "local"),
            "engine": threats.get("source", "mock"),
            "overall": threats.get("overall", "Low"),
            "counts": {"High": threats.get("counts", {}).get("High", 0),
                       "Medium": threats.get("counts", {}).get("Medium", 0),
                       "Low": threats.get("counts", {}).get("Low", 0)},
        },
        "devices": devices,
        "asserts": asserts,
        "findings": threats.get("findings", []),
        "ping": analysis.get("ping_check"),
        "topo_imgs": _topo_images(),
    }


def _topo_images():
    imgs = {}
    for name in ("layer3", "ospf", "bgp"):
        p = os.path.join(TOPO_DIR, f"{name}.png")
        if os.path.exists(p):
            imgs[name] = "file://" + p.replace("\\", "/")
    return imgs


def render_html(analysis, threats, devices):
    tpl = _env.from_string(get_template_text())
    return tpl.render(**_build_context(analysis, threats, devices))


def build_report(analysis, threats, out_path, devices=None):
    from weasyprint import HTML
    html = render_html(analysis, threats, devices or [])
    HTML(string=html, base_url=TEMPLATE_DIR).write_pdf(out_path)
    return out_path
