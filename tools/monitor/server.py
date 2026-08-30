"""Read-only HTTP server for the live stage monitor.

The monitor is a TV.  It renders the evidence a run already wrote and can do
nothing else: it answers ``GET`` and ``HEAD`` for a fixed set of routes, starts
no run, invokes no agent, wraps no ``foundryctl``, contacts no network service,
polls no forge, and never opens a file for writing.  Write methods are refused
with ``405`` rather than ignored, so the read-only boundary is visible from the
outside.

The only write this tool is ever permitted is the optional, deletable local
``.monitor-cache`` named by :data:`monitor.run_reader.CACHE_DIRNAME`.  This
server does not use it: serving a board leaves every byte on disk unchanged.

Run it from the repository that holds ``runs/``::

    PYTHONPATH=tools python3 -m monitor.server --root . --port 8787
    python3 tools/monitor/server.py --root . --port 8787
"""

from __future__ import annotations

import argparse
import json
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .run_reader import CACHE_DIRNAME, read_board, select_run_directory
except ImportError:  # executed as ``python3 tools/monitor/server.py``
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from monitor.run_reader import CACHE_DIRNAME, read_board, select_run_directory

__all__ = ["BOARD_PATH", "DECISION_SHEET_PATH", "MonitorHandler", "board_payload",
           "build_server", "main", "make_handler"]

STATIC_DIR = Path(__file__).resolve().parent / "static"
BOARD_PATH = "/api/board"
DECISION_SHEET_PATH = "/decision-sheet.md"
DECISION_SHEET_NAME = "decision-sheet.md"

# Every servable file is named here, so no request path is ever joined onto a
# filesystem path and no traversal is expressible.
STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/monitor.css": ("monitor.css", "text/css; charset=utf-8"),
    "/monitor.js": ("monitor.js", "text/javascript; charset=utf-8"),
}

JSON_TYPE = "application/json; charset=utf-8"
MARKDOWN_TYPE = "text/markdown; charset=utf-8"

# ``read_board`` globs ``runs/*-<task>-*``; "*" therefore follows the newest run
# of any task, which is what a wall display wants by default.
DEFAULT_TASK = "*"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787


def board_payload(root: Path, task: str) -> dict[str, Any]:
    """The board the page renders, plus the URL that opens its decision sheet."""
    board = read_board(Path(root), task)
    # The page is served over http, where a browser refuses a file:// link, so
    # the sheet is offered as a route instead of as the absolute path.
    board["decisionSheetUrl"] = DECISION_SHEET_PATH if board.get("decisionSheet") else None
    return board


class MonitorHandler(BaseHTTPRequestHandler):
    """Serves the one page, its two assets, the board and the decision sheet."""

    server_version = "foundry-monitor"
    sys_version = ""
    root: Path = Path.cwd()
    task: str = DEFAULT_TASK
    quiet: bool = False

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch name
        self._respond(with_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch name
        self._respond(with_body=False)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch name
        self._refuse_write()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch name
        self._refuse_write()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch name
        self._refuse_write()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch name
        self._refuse_write()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - base signature
        if not self.quiet:
            super().log_message(format, *args)

    # --- routing ---------------------------------------------------------

    def _respond(self, with_body: bool) -> None:
        path = urlsplit(self.path).path
        if path == BOARD_PATH:
            payload = json.dumps(board_payload(self.root, self.task), indent=2, sort_keys=True)
            self._send(HTTPStatus.OK, JSON_TYPE, payload.encode("utf-8"), with_body)
        elif path == DECISION_SHEET_PATH:
            self._send_decision_sheet(with_body)
        elif path in STATIC_ROUTES:
            name, content_type = STATIC_ROUTES[path]
            self._send_static(name, content_type, with_body)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "not found")

    def _send_decision_sheet(self, with_body: bool) -> None:
        """The sheet of the run the board is showing; the path is never taken from the URL."""
        run_dir = select_run_directory(self.root, self.task)
        sheet = None if run_dir is None else run_dir / DECISION_SHEET_NAME
        if sheet is None or not sheet.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "no decision sheet for the current run")
            return
        try:
            payload = sheet.read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "decision sheet is unreadable")
            return
        self._send(HTTPStatus.OK, MARKDOWN_TYPE, payload, with_body)

    def _send_static(self, name: str, content_type: str, with_body: bool) -> None:
        try:
            payload = (STATIC_DIR / name).read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "asset is missing")
            return
        self._send(HTTPStatus.OK, content_type, payload, with_body)

    def _send(self, status: HTTPStatus, content_type: str, payload: bytes, with_body: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        # A wall display must never show a run that has already been replaced.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if with_body:
            self.wfile.write(payload)

    def _refuse_write(self) -> None:
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "the monitor is read-only")


def make_handler(root: Path, task: str, quiet: bool = False) -> type[MonitorHandler]:
    """A handler class bound to the repository root and the task it follows."""

    class BoundMonitorHandler(MonitorHandler):
        pass

    BoundMonitorHandler.root = Path(root).resolve()
    BoundMonitorHandler.task = task
    BoundMonitorHandler.quiet = quiet
    return BoundMonitorHandler


def build_server(root: Path, task: str = DEFAULT_TASK, host: str = DEFAULT_HOST,
                 port: int = DEFAULT_PORT, quiet: bool = False) -> ThreadingHTTPServer:
    """A bound, not yet serving, local monitor server.  Port 0 picks a free port."""
    return ThreadingHTTPServer((host, port), make_handler(root, task, quiet))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the read-only live stage monitor.")
    parser.add_argument("--root", type=Path, default=Path.cwd(),
                        help="repository root that holds runs/ (default: the current directory)")
    parser.add_argument("--task", default=DEFAULT_TASK,
                        help="task id to follow (default: the newest run of any task)")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"interface to bind (default: {DEFAULT_HOST}, local only)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port to bind (default: {DEFAULT_PORT}, 0 picks a free port)")
    parser.add_argument("--quiet", action="store_true", help="do not log requests")
    args = parser.parse_args(argv)

    server = build_server(args.root, args.task, args.host, args.port, args.quiet)
    host, port = server.server_address[:2]
    print(f"monitor: http://{host}:{port}/ — read-only, following {args.task} "
          f"under {Path(args.root).resolve()}/runs (no writes outside {CACHE_DIRNAME})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - operator entry point
    raise SystemExit(main())
