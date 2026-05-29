"""
Flask web frontend for OSINT Agent.

Routes:
    GET  /                      - Landing page
    POST /scan                  - Start a scan
    GET  /scan/<id>             - Live progress page
    GET  /scan/<id>/stream      - SSE progress stream
    GET  /scan/<id>/results     - Results dashboard
    GET  /files/<path>          - Serve generated reports/graphs
"""
import json
import queue
import threading
import uuid
from pathlib import Path

from flask import Flask, Response, redirect, render_template, request, send_file, url_for

from agents.orchestrator import OSINTOrchestrator
from database.db import get_all_records, get_record_detail, insert_scan_files, get_scan_files
from output.graph_visualizer import save_graph
from output.report_generator import save_html_report, save_text_report, save_pdf_report

app = Flask(__name__, template_folder="templates", static_folder="static")

# In-memory scan store: scan_id -> {queue, findings, error, done, target, graph_path, report_path}
_scans: dict = {}


# ── Background scan thread ─────────────────────────────────────────────────────

def _run_scan(scan_id: str, target: str):
    q = _scans[scan_id]["queue"]

    def emit(msg: str):
        q.put(msg)

    try:
        orchestrator = OSINTOrchestrator(progress_cb=emit)
        findings = orchestrator.run(target)
        _scans[scan_id]["findings"] = findings

        emit("[*] Generating reports...")
        txt_path = save_text_report(findings)
        html_path = save_html_report(findings)
        graph_path = save_graph(findings)
        pdf_path = save_pdf_report(findings)

        json_path = txt_path.with_suffix(".json")
        serializable = {k: v for k, v in findings.items() if isinstance(v, (str, int, float, list, dict))}
        json_path.write_text(json.dumps(serializable, indent=2, default=str), encoding="utf-8")

        _scans[scan_id]["txt_path"] = str(txt_path)
        _scans[scan_id]["html_path"] = str(html_path)
        _scans[scan_id]["graph_path"] = str(graph_path)
        _scans[scan_id]["pdf_path"] = str(pdf_path) if pdf_path else None
        _scans[scan_id]["json_path"] = str(json_path)

        target_id = findings.get("target_id")
        if target_id:
            insert_scan_files(
                target_id,
                graph_path=str(graph_path),
                html_path=str(html_path),
                txt_path=str(txt_path),
                json_path=str(json_path),
            )

        emit("[+] All reports saved.")
        q.put("__DONE__")
    except Exception as exc:
        _scans[scan_id]["error"] = str(exc)
        q.put(f"__ERROR__{exc}")
    finally:
        _scans[scan_id]["done"] = True


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    static = Path("static")
    return render_template(
        "index.html",
        logo_exists=(static / "logo.png").exists(),
        hero_exists=(static / "hero.png").exists(),
    )


@app.route("/about")
def about_page():
    return render_template("page.html", page="about")


@app.route("/features")
def features_page():
    return render_template("page.html", page="features")


@app.route("/api")
def api_page():
    return render_template("page.html", page="api")


@app.route("/docs")
def docs_page():
    return render_template("page.html", page="docs")


@app.route("/records")
def records_page():
    records = get_all_records()
    return render_template("records.html", records=records)


@app.route("/records/<int:target_id>")
def record_detail(target_id: int):
    data = get_record_detail(target_id)
    if not data:
        return redirect(url_for("records_page"))
    files = get_scan_files(target_id)
    return render_template(
        "results.html",
        scan_id=f"db-{target_id}",
        target=data.get("input", ""),
        findings=data,
        has_pdf=False,
        db_files=files,
    )


@app.route("/records/<int:target_id>/graph")
def record_graph(target_id: int):
    # Prefer a saved graph; otherwise regenerate from stored findings.
    files = get_scan_files(target_id)
    path = files.get("graph_path")
    if path and Path(path).exists():
        return send_file(path)
    data = get_record_detail(target_id)
    if not data:
        return "Record not found", 404
    return save_graph(data).read_text(encoding="utf-8")


@app.route("/records/<int:target_id>/download/<filetype>")
def record_download(target_id: int, filetype: str):
    # Prefer a saved file; otherwise regenerate from stored findings.
    files = get_scan_files(target_id)
    key_map = {"html": "html_path", "txt": "txt_path", "json": "json_path"}
    path = files.get(key_map.get(filetype, ""))
    if path and Path(path).exists():
        return send_file(path, as_attachment=True)

    data = get_record_detail(target_id)
    if not data:
        return "Record not found", 404

    if filetype == "html":
        return send_file(save_html_report(data), as_attachment=True)
    if filetype == "txt":
        return send_file(save_text_report(data), as_attachment=True)
    if filetype == "pdf":
        pdf = save_pdf_report(data)
        if not pdf:
            return "PDF generation unavailable", 500
        return send_file(pdf, as_attachment=True)
    if filetype == "json":
        serializable = {k: v for k, v in data.items()
                        if isinstance(v, (str, int, float, list, dict))}
        return Response(
            json.dumps(serializable, indent=2, default=str),
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{data.get("input","record")}.json"'},
        )
    return "File not found", 404


@app.route("/scan", methods=["POST"])
def start_scan():
    target = request.form.get("target", "").strip()
    if not target:
        return redirect(url_for("index"))

    scan_id = uuid.uuid4().hex[:8]
    _scans[scan_id] = {
        "queue": queue.Queue(),
        "findings": None,
        "error": None,
        "done": False,
        "target": target,
        "txt_path": None,
        "html_path": None,
        "graph_path": None,
        "json_path": None,
    }
    threading.Thread(target=_run_scan, args=(scan_id, target), daemon=True).start()
    return redirect(url_for("scan_page", scan_id=scan_id))


@app.route("/scan/<scan_id>")
def scan_page(scan_id: str):
    if scan_id not in _scans:
        return redirect(url_for("index"))
    return render_template("scan.html", scan_id=scan_id, target=_scans[scan_id]["target"])


@app.route("/scan/<scan_id>/stream")
def scan_stream(scan_id: str):
    def generate():
        if scan_id not in _scans:
            yield "data: __ERROR__Scan not found\n\n"
            return
        q = _scans[scan_id]["queue"]
        while True:
            try:
                msg = q.get(timeout=30)
                yield f"data: {msg}\n\n"
                if msg == "__DONE__" or msg.startswith("__ERROR__"):
                    break
            except queue.Empty:
                yield "data: __PING__\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/scan/<scan_id>/results")
def results_page(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan or not scan["findings"]:
        return redirect(url_for("scan_page", scan_id=scan_id))
    return render_template(
        "results.html",
        scan_id=scan_id,
        target=scan["target"],
        findings=scan["findings"],
        has_pdf=bool(scan.get("pdf_path")),
    )


@app.route("/scan/<scan_id>/graph")
def view_graph(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan or not scan.get("graph_path"):
        return "Graph not ready", 404
    return send_file(scan["graph_path"])


@app.route("/scan/<scan_id>/download/<filetype>")
def download_report(scan_id: str, filetype: str):
    scan = _scans.get(scan_id)
    if not scan:
        return "Scan not found", 404
    paths = {
        "txt": scan.get("txt_path"),
        "html": scan.get("html_path"),
        "json": scan.get("json_path"),
        "pdf": scan.get("pdf_path"),
    }
    path = paths.get(filetype)
    if not path or not Path(path).exists():
        return "File not found", 404
    return send_file(path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)
