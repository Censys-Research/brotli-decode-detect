#!/usr/bin/env python3
# Benign "is Brotli request decoding active?" probe (v3.1).
# Sends only VALID Brotli streams; never a malformed one, so it cannot trigger
# CVE-2026-111497. It answers "does this endpoint decode br request bodies", not
# "is it vulnerable": a patched and an unpatched decoder behave identically on
# valid input. Only point it at hosts you own or are authorized to test.
#
# Method (semantic differential). Per path and content type, send:
#   p_ok    plain, valid body                     p_bad   plain, INVALID body
#   b_ok    br-declared, decodes to valid body    b_bad   br-declared, decodes to INVALID body
#   b_decoy br-declared, decodes to INVALID body but its wire bytes also contain the valid body
#   n_ok    the same br bytes as b_ok, header omitted    p_ok2   plain valid again (stability)
# ACTIVE requires all of:
#   * the app reacts to body content at all (p_ok != p_bad)
#   * b_ok behaves like p_ok, b_bad like p_bad, AND b_decoy like p_bad (the response tracks the
#     DECODED content, not the wire bytes)
#   * n_ok differs from p_ok (so the header is what made the difference)
#   * no rate-limit/gateway statuses, a stable control, and the result reproduces with the
#     request order reversed.
# A server that merely skips parsing when Content-Encoding is present, a lenient substring matcher
# (alone or behind a WAF), a rate limiter, or a flaky backend each fail at least one of these.
# Cells whose plain pair shows the response does not depend on body content stop after 2 requests,
# and the gzip/bogus-encoding annotations are only sent for cells that reach a negative verdict.

import gzip as gzip_mod
import io
import ipaddress
import random
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

# A Brotli stream with one uncompressed metablock, so no compressor is needed.
# Bits (LSB first): WBITS=16 (0), ISLAST=0, MNIBBLES=4 (00), MLEN-1 (16 bits),
# ISUNCOMPRESSED=1, pad to byte; then raw bytes; then an empty last metablock.
def brotli_stored(data: bytes) -> bytes:
    if len(data) > 65_536:
        raise ValueError("payload too large")
    header = ((len(data) - 1) << 4) | (1 << 20)
    return bytes([header & 0xFF, (header >> 8) & 0xFF, (header >> 16) & 0xFF]) + data + b"\x03"


# Decodes to exactly `real`, but the wire bytes also contain `decoy` inside a metadata meta-block,
# which decoders skip (RFC 7932 section 9.2). A server that reads the wire bytes instead of decoding
# them, such as a lenient substring matcher, sees the decoy; a real decoder never does.
# Metadata meta-block: WBITS=16 (0), ISLAST=0, MNIBBLES=3 (11), reserved 0, MSKIPBYTES=1 (01),
# MSKIPLEN-1 (8 bits), pad to byte; then the skipped bytes; then a stored meta-block as above.
def brotli_decoy(decoy: bytes, real: bytes) -> bytes:
    if not (1 <= len(decoy) <= 256):
        raise ValueError("decoy must be 1..256 bytes")
    if len(real) > 65_536:
        raise ValueError("payload too large")
    skip = 0x0C | 0x20 | ((len(decoy) - 1) << 7)
    stored = ((len(real) - 1) << 3) | (1 << 19)  # ISLAST=0, MNIBBLES=4 (00), MLEN-1, ISUNCOMPRESSED=1
    return (
        bytes([skip & 0xFF, (skip >> 8) & 0xFF])
        + decoy
        + bytes([stored & 0xFF, (stored >> 8) & 0xFF, (stored >> 16) & 0xFF])
        + real
        + b"\x03"
    )


def gzip_bytes(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip_mod.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(data)
    return buf.getvalue()


# [valid, invalid] body per content type. Invalid bodies are still valid *Brotli* once wrapped.
PAYLOADS = {
    "application/json": (b'{"probe":1}', b'{"probe":'),
    "application/x-www-form-urlencoded": (b"probe=1", b"other=2"),
}

# Statuses that say "the network or a limiter answered", never "the app parsed my body".
UNTRUSTED = {408, 425, 429, 502, 503, 504}


@dataclass
class Target:
    host: str
    port: int
    tls: bool


@dataclass
class Result:
    status: int = 0
    snippet: str = ""
    norm: str = ""

    @classmethod
    def error(cls, exc: Exception) -> "Result":
        return cls(status=0, snippet=type(exc).__name__, norm=type(exc).__name__)

    def sig(self) -> tuple:
        return (self.status, self.norm)


# Mask request ids, timestamps and counters so dynamic bodies still compare equal.
def normalize(text: str) -> str:
    # Body snippets are truncated, so a UUID may be cut mid-way: mask any hex/dash run,
    # not just whole UUIDs.
    text = re.sub(r"[0-9a-f][0-9a-f-]{5,}", "#", text, flags=re.IGNORECASE)
    return re.sub(r"\d+", "#", text)


# Never follow redirects. urllib would turn a redirected POST into a GET that keeps the
# Content-Encoding header but drops the body (an empty, invalid Brotli stream), possibly sent to a
# host the user never named. A 3xx is a response like any other: it is raised as an HTTPError below
# and recorded as the status.
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_post(target: Target, path: str, ctype: str, encoding, body: bytes) -> Result:
    try:
        scheme = "https" if target.tls else "http"
        url = f"{scheme}://{target.host}:{target.port}{path}"
        # Behavior probe, not a trust decision: do not verify certificates.
        handlers = [_NoRedirect()]
        if target.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", ctype)
        if encoding:
            req.add_header("Content-Encoding", encoding)
        with opener.open(req, timeout=5) as res:
            code, raw = res.status, res.read()
        snippet = re.sub(r"\s+", " ", raw.decode("utf-8", "replace")[:60])
        return Result(code, snippet, normalize(snippet))
    except urllib.error.HTTPError as e:
        raw = e.read()
        snippet = re.sub(r"\s+", " ", raw.decode("utf-8", "replace")[:60])
        return Result(e.code, snippet, normalize(snippet))
    except Exception as e:
        return Result.error(e)


# TLS detection: True = TLS, False = plain HTTP, None = could not connect at all.
def detect_tls(host: str, port: int):
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except (OSError, socket.timeout):
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ipaddress.ip_address(host)
            server_hostname = None  # IP literal: no SNI
        except ValueError:
            server_hostname = host
        try:
            ctx.wrap_socket(sock, server_hostname=server_hostname)
            return True
        except (ssl.SSLError, EOFError, ConnectionResetError, OSError):
            return False
    finally:
        sock.close()


CORE = ["p_ok", "p_bad", "b_ok", "b_bad", "b_decoy", "n_ok", "p_ok2"]
CONFIRM_ORDER = ["n_ok", "b_decoy", "b_bad", "b_ok", "p_bad", "p_ok", "p_ok2"]  # same requests, reversed


# name => [Content-Encoding or None, body]
def request_set(ctype: str) -> dict:
    ok, bad = PAYLOADS[ctype]
    return {
        "p_ok": (None, ok),
        "p_bad": (None, bad),
        "b_ok": ("br", brotli_stored(ok)),
        "b_bad": ("br", brotli_stored(bad)),
        "b_decoy": ("br", brotli_decoy(ok, bad)),  # decodes to the INVALID body; wire bytes contain the valid one
        "n_ok": (None, brotli_stored(ok)),
        "p_ok2": (None, ok),
        "g_ok": ("gzip", gzip_bytes(ok)),
        "bogus": ("xyz", ok),
    }


def run_requests(target: Target, path: str, ctype: str, order: list) -> dict:
    set_ = request_set(ctype)
    return {name: send_post(target, path, ctype, *set_[name]) for name in order}


# Transport errors and limiter/gateway statuses among the named requests: never an answer.
def noise_verdict(r: dict, names: list):
    if any(r[n].status == 0 for n in names):
        return ["NO RESPONSE", "connection errors"]
    noisy = next((r[n].status for n in names if r[n].status in UNTRUSTED), None)
    if noisy:
        return ["INCONCLUSIVE", f"untrusted status {noisy} (rate limit or gateway noise)"]
    return None


def no_signal_verdict(status: int):
    return ["NO SIGNAL", f"response does not depend on body content (valid and invalid plain bodies look alike: {status})"]


# Decided from the plain pair alone. When the pair is noisy, errored, a 5xx, or looks alike, classify()
# can only ever return a non-answer (NO RESPONSE / INCONCLUSIVE / NO SIGNAL) whatever the other
# requests say, so the rest of the cell is not sent. Never changes an ACTIVE / NOT ACTIVE / AMBIGUOUS result.
def early_verdict(r: dict):
    noise = noise_verdict(r, ["p_ok", "p_bad"])
    if noise:
        return noise
    if r["p_ok"].status >= 500:
        return ["INCONCLUSIVE", "5xx on a valid-body request (backend error, not a parse result)"]
    if r["p_ok"].sig() == r["p_bad"].sig():
        return no_signal_verdict(r["p_ok"].status)
    return None


# Returns [verdict, detail] from one (path, content-type) cell. With lazy=True it returns
# ["need_annotations", None] when the cell reaches the negative verdicts (the only place the gzip and
# bogus-encoding annotations are consulted) and they have not been collected yet.
def classify(r: dict, lazy: bool = False):
    p_ok, p_bad, b_ok, b_bad, b_decoy, n_ok, p_ok2 = (r[n].sig() for n in CORE)
    noise = noise_verdict(r, CORE)
    if noise:
        return noise
    if p_ok != p_ok2:
        return ["INCONCLUSIVE", "unstable: the repeated plain request answered differently"]
    # A 5xx on a body that should have parsed is app/backend noise, not a parse verdict.
    if any(r[n].status >= 500 for n in ("p_ok", "b_ok", "n_ok")):
        return ["INCONCLUSIVE", "5xx on a valid-body request (backend error, not a parse result)"]
    if p_ok == p_bad:
        return no_signal_verdict(r["p_ok"].status)

    if b_ok == p_ok:
        if b_bad != p_bad:
            return ["AMBIGUOUS", "br valid body matched plain but br invalid body did not: header may bypass parsing, not counted as decoding"]
        # The decoy decodes to an invalid body but its wire bytes contain a valid one: only a server
        # that reads wire bytes instead of decoded content can treat it as valid.
        if b_decoy != p_bad:
            return ["AMBIGUOUS", "a br body whose decoded content is invalid but whose wire bytes hold a valid token was accepted: the server reads wire bytes, not decoded content"]
        if n_ok == p_ok:
            return ["AMBIGUOUS", "undeclared br bytes were accepted like a plain body; cannot attribute to decoding"]
        return ["ACTIVE", f"responses track decoded content (valid {r['b_ok'].status}, invalid {r['b_bad'].status}); undeclared bytes gave {r['n_ok'].status}"]

    if lazy and "g_ok" not in r:
        return ["need_annotations", None]

    gz_note = ""
    if "g_ok" in r:
        gz_note = "; gzip IS decoded" if r["g_ok"].sig() == p_ok else "; gzip not decoded either"
    # An explicit refusal naming the encoding is trustworthy even without a 2xx control.
    if re.search(r"content-encoding|unsupported|brotli|install", r["b_ok"].snippet, re.IGNORECASE) and not re.search(
        r"content-encoding|unsupported|brotli", r["p_ok"].snippet, re.IGNORECASE
    ):
        return ["NOT ACTIVE", f"explicit br refusal ({r['b_ok'].status}: {r['b_ok'].snippet[:40]}){gz_note}"]
    # Other negatives need a path that really consumed the plain body; on a 404 path decoding
    # hooks may simply not be attached (seen with Fastify route-level hooks).
    if not 200 <= r["p_ok"].status <= 299:
        return ["INCONCLUSIVE", f"plain control was {r['p_ok'].status}, path may not consume bodies (br {r['b_ok'].status})"]
    if r.get("bogus") and r["bogus"].sig() == b_ok:
        return ["NOT ACTIVE", f"br rejected like an unknown encoding ({r['b_ok'].status}){gz_note}"]
    if b_ok == n_ok:
        return ["NOT ACTIVE", f"Content-Encoding ignored (br {r['b_ok'].status} with or without header){gz_note}"]

    return ["AMBIGUOUS", f"plain {r['p_ok'].status}, br {r['b_ok'].status}, undeclared {r['n_ok'].status}"]


@dataclass
class Cell:
    path: str
    ctype: str
    results: dict = field(default_factory=dict)
    verdict: str = ""
    detail: str = ""


def probe_cell(target: Target, path: str, ctype: str, annotate: bool = True) -> Cell:
    cell = Cell(path=path, ctype=ctype)
    cell.results = run_requests(target, path, ctype, ["p_ok", "p_bad"])
    verdict_detail = early_verdict(cell.results)
    if not verdict_detail:
        missing = [n for n in CORE if n not in cell.results]
        cell.results.update(run_requests(target, path, ctype, missing))
        verdict, detail = classify(cell.results, lazy=annotate)
        if verdict == "need_annotations":
            # gzip and bogus-encoding only feed the negative verdicts, so only cells that reach
            # them pay for them.
            cell.results.update(run_requests(target, path, ctype, ["g_ok", "bogus"]))
            verdict, detail = classify(cell.results)
        verdict_detail = [verdict, detail]
    verdict, detail = verdict_detail
    if verdict == "ACTIVE":
        # Confirmation: same questions, reversed order. A limiter or flaky backend will not repeat itself.
        again = run_requests(target, path, ctype, CONFIRM_ORDER)
        v2, d2 = classify(again)
        if v2 != "ACTIVE":
            verdict, detail = "AMBIGUOUS", f"positive did not reproduce with reversed order ({v2}: {d2})"
    cell.verdict, cell.detail = verdict, detail
    return cell


OVERALL_ORDER = ["ACTIVE", "NOT ACTIVE", "AMBIGUOUS", "INCONCLUSIVE", "NO SIGNAL", "NO RESPONSE"]


def random_path() -> str:
    return "/" + "".join(random.choice("0123456789abcdef") for _ in range(8))


# tls: "auto" (try TLS, fall back to plain), True, or False.
# stop_on_active: True ends the sweep at the first confirmed ACTIVE cell. The overall verdict is
# "ACTIVE if any cell is ACTIVE", so later cells cannot change it; they would only add per-cell
# diagnostics. Cuts the worst case down substantially. Leave it off when you want the full picture.
def probe(host, port, paths=None, tls="auto", annotate=True, stop_on_active=False):
    if tls == "auto":
        tls = detect_tls(host, port) is True
    target = Target(host, port, tls)
    if paths is None:
        paths = ["/", random_path()]
    cells = []
    for path in paths:
        for ctype in PAYLOADS:
            cells.append(probe_cell(target, path, ctype, annotate=annotate))
            if stop_on_active and cells[-1].verdict == "ACTIVE":
                overall = next(v for v in OVERALL_ORDER if any(c.verdict == v for c in cells))
                return overall, cells, target
    overall = next(v for v in OVERALL_ORDER if any(c.verdict == v for c in cells))
    return overall, cells, target


def print_probe(overall, cells, target, verbose=False):
    print(f"  {'https' if target.tls else 'http'}://{target.host}:{target.port}")
    for c in cells:
        print(f"  {c.path:<12} {c.ctype:<34} {c.verdict:<12} {c.detail}")
        if verbose:
            for name, r in c.results.items():
                print(f"      {name:<7} {r.status:>3}  {r.snippet}")
    print(f"  => {overall}")


USAGE = """usage: brotli-request-decode-probe.py [--tls on|off|auto] [--core] [--first-active] [--quiet] HOST[:PORT] [PORT] [PATH...]
       brotli-request-decode-probe.py [--core] [--quiet] http(s)://HOST[:PORT][/PATH] [PATH...]
Default port: 443 for https / --tls on, 80 for http / --tls off. With no scheme and no
port, --tls auto tries TLS on 443 first, then plain HTTP on 80."""


# Returns (host, port, paths, opts dict); port is None when it should be defaulted.
def parse_args(argv):
    opts = {"tls": "auto", "annotate": True, "verbose": True, "stop_on_active": False}
    rest = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--tls":
            i += 1
            if i >= len(argv) or argv[i] not in ("on", "off", "auto"):
                sys.exit(USAGE)
            opts["tls"] = argv[i]
        elif arg == "--core":
            opts["annotate"] = False
        elif arg == "--first-active":
            opts["stop_on_active"] = True
        elif arg == "--quiet":
            opts["verbose"] = False
        elif arg in ("-h", "--help"):
            sys.exit(USAGE)
        else:
            rest.append(arg)
        i += 1
    if not rest:
        sys.exit(USAGE)

    first = rest.pop(0)
    host = port = None
    paths = rest
    opts["tls"] = {"on": True, "off": False, "auto": "auto"}[opts["tls"]]
    if re.match(r"^https?://", first):
        from urllib.parse import urlparse
        u = urlparse(first)
        opts["tls"] = u.scheme == "https"
        host = u.hostname
        port = u.port
        if u.path:
            paths = [u.path] + rest
    elif re.match(r"^[^:/]+:(\d+)$", first):
        host, _, p = first.partition(":")
        port = int(p)
    else:
        host = first
        if rest and rest[0].isdigit():
            port = int(rest.pop(0))
    if paths and not all(p.startswith("/") for p in paths):
        sys.exit(f"paths must start with /\n{USAGE}")
    return host, port, paths, opts


# Fills in a missing port, and the scheme with it when TLS is on auto.
def resolve_port(host, port, tls):
    if port:
        return port, tls
    if tls != "auto":
        return (443 if tls else 80), tls
    if detect_tls(host, 443) is True:
        return 443, True
    return 80, False


def main():
    host, port, paths, opts = parse_args(sys.argv[1:])
    port, tls = resolve_port(host, port, opts["tls"])
    overall, cells, target = probe(
        host, port, paths or None, tls=tls, annotate=opts["annotate"], stop_on_active=opts["stop_on_active"]
    )
    print_probe(overall, cells, target, verbose=opts["verbose"])


if __name__ == "__main__":
    main()
