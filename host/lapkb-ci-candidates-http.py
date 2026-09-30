#!/usr/bin/env python3
"""Token-protected HTTP frontend for private build candidates.

PUT /ci-candidates/v1/chunk/<app>/<sha>/<target>/<archive-sha>/<index>
    Fixed-length body (at most 32 MiB); X-Candidate-Chunk-SHA256 is required.
POST /ci-candidates/v1/put/<app>/<sha>/<target>/<archive-sha>
    No body; X-Candidate-Chunks/Bytes/Run/Attempt identify the completed upload.
DELETE /ci-candidates/v1/pending/<app>/<sha>/<target>/<archive-sha>
    Abort an incomplete upload without touching retained candidates.
DELETE /ci-candidates/v1/remove/<app>/<sha>
    Remove a wave after its verified final binaries exist.
GET /ci-candidates/v1/list
    Return retained receipts without modifying global stdout.

LAPKB_CI_CANDIDATES_TOKEN_FILE is required. Bind defaults to 127.0.0.1:8791.
"""

import hmac
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

CORE_PATH = Path(__file__).with_name("lapkb-ci-candidates.py")
spec = importlib.util.spec_from_file_location("lapkb_ci_candidates", CORE_PATH)
if spec is None or spec.loader is None:
    raise SystemExit("candidate store: cannot load storage core")
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
SEMAPHORE = threading.BoundedSemaphore(4)


def read_token():
    path = os.environ.get("LAPKB_CI_CANDIDATES_TOKEN_FILE")
    if not path:
        raise SystemExit("candidate store: LAPKB_CI_CANDIDATES_TOKEN_FILE is required")
    try:
        with open(path, "rb") as handle:
            token = handle.read(4096).strip()
    except OSError as error:
        raise SystemExit("candidate store: cannot read token file") from error
    if len(token) != 64 or any(c not in b"0123456789abcdef" for c in token):
        raise SystemExit("candidate store: invalid token format")
    return token


class LimitedReader:
    """Read exactly the declared body, never a following request."""

    def __init__(self, stream, size):
        self.stream = stream
        self.remaining = size

    def read(self, size):
        data = self.stream.read(min(self.remaining, size))
        self.remaining -= len(data)
        return data


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "lapkb-ci-candidates"
    token = b""

    def setup(self):
        super().setup()
        self.connection.settimeout(120)

    def log_message(self, format, *args):  # noqa: A002 - BaseHTTPRequestHandler signature
        sys.stderr.write("candidate store: %s\n" % (format % args))

    def respond(self, status, value):
        payload = (json.dumps(value, sort_keys=True) + "\n").encode()
        # Always close: rejected/unauthorized bodies must not be interpreted as
        # another HTTP request (the previous server could return spurious 501s).
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def route(self):
        headers = self.headers.get_all("Authorization", [])
        if len(headers) != 1 or not headers[0].startswith("Bearer "):
            raise core.CandidateError("missing or invalid token", 401)
        if not hmac.compare_digest(headers[0][7:].encode(), self.token):
            raise core.CandidateError("missing or invalid token", 401)
        path = urlsplit(self.path)
        if path.query or path.fragment:
            raise core.CandidateError("unknown route", 404)
        parts = path.path.split("/")
        if parts[:3] != ["", "ci-candidates", "v1"] or any(not p for p in parts[3:]):
            raise core.CandidateError("unknown route", 404)
        return parts[3:]

    def integer_header(self, name):
        values = self.headers.get_all(name, [])
        if len(values) != 1 or not values[0].isascii() or not values[0].isdigit() or len(values[0]) > 12:
            raise core.CandidateError("invalid or missing " + name, 411 if name == "Content-Length" else 400)
        try:
            return int(values[0])
        except ValueError as error:
            raise core.CandidateError("invalid " + name) from error

    def no_body(self):
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
            raise core.CandidateError("this route accepts no request body")

    def dispatch(self, method):
        acquired = False
        try:
            parts = self.route()
            if method == "GET" and parts == ["list"]:
                self.no_body()
                self.respond(200, core.listing())
                return
            if method == "DELETE" and len(parts) == 3 and parts[0] == "remove":
                self.no_body()
                core.remove(parts[1], parts[2])
                self.respond(200, {"removed": parts[1], "sourceSha": parts[2]})
                return
            if method == "DELETE" and len(parts) == 5 and parts[0] == "pending":
                self.no_body()
                core.abort(*parts[1:])
                self.respond(200, {"aborted": True})
                return
            if not ((method == "PUT" and len(parts) == 6 and parts[0] == "chunk")
                    or (method == "POST" and len(parts) == 5 and parts[0] == "put")):
                raise core.CandidateError("unknown route", 404)
            acquired = SEMAPHORE.acquire(blocking=False)
            if not acquired:
                raise core.CandidateError("too many concurrent uploads", 429)
            if method == "PUT":
                if self.headers.get("Transfer-Encoding"):
                    raise core.CandidateError("chunked HTTP encoding is not accepted")
                size = self.integer_header("Content-Length")
                if not 0 < size <= core.MAX_CHUNK_BYTES:
                    raise core.CandidateError("chunk exceeds its size bound", 413)
                if not parts[5].isascii() or not parts[5].isdigit() or len(parts[5]) > 4:
                    raise core.CandidateError("invalid chunk index")
                core.write_chunk(*parts[1:5], int(parts[5]),
                                 self.headers.get("X-Candidate-Chunk-SHA256", ""),
                                 LimitedReader(self.rfile, size), size)
                self.respond(200, {"chunk": int(parts[5]), "bytes": size})
            else:
                self.no_body()
                receipt = core.finish(*parts[1:], self.integer_header("X-Candidate-Chunks"),
                                      self.integer_header("X-Candidate-Bytes"),
                                      self.headers.get("X-Candidate-Run", "0"),
                                      self.headers.get("X-Candidate-Attempt", "0"))
                self.respond(201, {key: value for key, value in receipt.items() if key != "inventory"})
        except core.CandidateError as error:
            self.respond(error.status, {"error": error.message})
        except (OSError, socket.timeout):
            self.respond(500, {"error": "candidate storage I/O failed"})
        finally:
            if acquired:
                SEMAPHORE.release()

    def do_PUT(self):
        self.dispatch("PUT")

    def do_POST(self):
        self.dispatch("POST")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def do_GET(self):
        self.dispatch("GET")


def main():
    bind = os.environ.get("LAPKB_CI_CANDIDATES_BIND", "127.0.0.1:8791")
    host, separator, port_text = bind.rpartition(":")
    try:
        port = int(port_text)
    except ValueError as error:
        raise SystemExit("candidate store: invalid bind address") from error
    if not separator or not 1 <= port <= 65535:
        raise SystemExit("candidate store: invalid bind address")
    Handler.token = read_token()
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    print(f"candidate store: listening on {bind}", file=sys.stderr, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
