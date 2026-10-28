# Censys ARC - Brotli request-decode detection

Two equivalent tools answer one question about an HTTP endpoint:

> **Does this endpoint decode `Content-Encoding: br` request bodies?**

That is the precondition for Node2Shell (CVE-2026-111497) and the same Brotli
out-of-bounds write in any other stack: an attacker can only reach the decoder
if the application feeds request bodies to it. Neither tool answers "is it
vulnerable" or "is it patched" - a patched and an unpatched decoder behave
identically on the inputs these tools send. Version confirmation needs
out-of-band data (package inventories, runtime versions, SBOMs).

| File | What it is |
|---|---|
| `brotli-request-decode-detect.yaml` | Nuclei template (JavaScript protocol), single request burst |
| `brotli-request-decode-probe.py` | Standalone Python 3 probe (stdlib only, no pip packages), multi-path / multi-content-type |

Both tools implement the same methodology; use whichever fits the tooling.
Created by **Censys ARC**; distributed as-is, without warranty or support
commitments.

## Safety properties (both tools)

- **Only valid Brotli streams are ever sent.** Every `br`-encoded body is an
  RFC 7932-valid stream built by hand and byte-verified against reference
  decoders. No malformed, truncated, or fuzzed input is ever sent, so the tools
  **cannot trigger the vulnerability**. A decoder crash cannot be caused by
  these probes by construction.
- **Small payloads.** Brotli bodies are at most a few dozen bytes in practice
  (the code's hard cap is 65,536); plain bodies are a few bytes of JSON.
- **Read-only semantics.** The probes only POST to existing endpoints; they do
  not attempt exploit payloads, file writes, callbacks, or anything beyond
  observing how the endpoint treats different request bodies.
- **Redirects are never followed.** A 3xx is recorded as the endpoint's
  response. Following one would send the request, minus its body, to whatever
  host the redirect names.
- Only scan hosts you own or are explicitly authorized to test.

## How the detection works

The core differential is behavioral. For a chosen path and content type, the
tools compare how the endpoint responds to:

| Request | Content-Encoding | Body (decoded) |
|---|---|---|
| `p_ok` | none | valid body (`{"probe":1}`) |
| `p_bad` | none | invalid body (`{"probe":`) |
| `b_ok` | `br` | valid body, wrapped in a valid Brotli stream |
| `b_bad` | `br` | invalid body, wrapped in a valid Brotli stream |
| `b_decoy` | `br` | invalid body, but the raw stream bytes also contain the valid token in a metadata block every decoder skips |
| `n_ok` | none | the `b_ok` stream bytes, raw, without the header |
| `p_ok2` | none | `p_ok` repeated (stability control) |

Verdict logic (strongest wins):

- **ACTIVE** - the response tracks *decoded* content: `b_ok` matches `p_ok`,
  `b_bad` matches `p_bad`, the decoy matches `b_bad` (proving the server
  processes decoded bytes, not raw bytes), `n_ok` differs (proving the header
  drives the decoding), the plain control is stable, and the whole decisive
  sequence reproduces in reversed order. Only this verdict means "Brotli
  request decoding is active at this URL".
- **NOT ACTIVE** - `br` was explicitly refused, or ignored, on a path that
  demonstrably consumed a plain body.
- **AMBIGUOUS** - something differed but cannot be attributed to decoding
  (e.g. the header makes the server skip parsing).
- **INCONCLUSIVE** - rate limiting, 5xx, gateway noise, unstable control, or a
  control path that does not consume bodies.
- **NO SIGNAL** - the response does not depend on body content at all (auth
  gate, static site). Never report this as "safe".

The conservatism is deliberate: every guard exists to prevent a false ACTIVE,
and the design goal is that an endpoint that does not decode Brotli is never
reported ACTIVE. No false positive was observed in the reference lab, but the
guards are statistical for some server behaviors; see "Known limits".

## Request count and shape

**Nuclei template**: roughly 8-21 POST requests, all the same shape:
small POSTs to one or a few paths with `Content-Type: application/json`, half
with a plain JSON body and half with a `br`-declared body of at most a few
  dozen bytes.
Route discovery sends the plain valid/invalid pair to each candidate path in
turn and stops at the first path that consumes a 2xx body. The default
candidate order is `/`, `/echo`, `/api`, `/` (the `path` variable defaults to
`/`, so `/` appears twice); `-V path=/real/route` is tried first, ahead of
`/echo`, `/api`, and `/`. A site that does not react to body content costs 8
requests (4 candidates x 2). A positive costs the route discovery (2 requests
per candidate tried), 5 core requests, and a reversed-order replay of 6 more,
about 13-15 when the first candidate matches and up to about 21 when the last
one does, plus one or two extra requests while it settles on plain versus TLS.
Requests are indistinguishable from normal API traffic except for the
`User-Agent` (`brotli-capability-probe/1.0`) and the `Content-Encoding: br`
header on the Brotli half.

**brotli-request-decode-probe.py**: by default 2 paths x 2 content types = 4
cells. A cell costs 2 requests when the response does not depend on the body
(early exit), 9 when it reaches a negative verdict (7 core requests plus a gzip
and an unknown-encoding annotation; 7 with `--core`), and 14 when it reaches
ACTIVE (7 core plus a 7-request reversed-order replay). Worst case is
therefore **56 requests**, four ACTIVE cells, and `--core` does not lower it.
Measured on loopback servers: 56 for a decoder on every path and content type;
14 with `--first-active`; 36 for a server that rejects every
`Content-Encoding`; 8 on a static site. A decoder on the JSON type only costs
32 when the form cells show no body dependence and 46 when they read NOT
ACTIVE, so "32" is one scenario, not a typical figure. An unresponsive host
costs 8 failed request attempts, plus one connect for TLS detection in the
default `--tls auto` mode. Pass more paths to widen coverage; each added path
adds 2 cells at the same per-cell costs.

## Usage

Nuclei (tested on v3.11.0; JavaScript templates must be signed or run with
unsigned templates allowed):

```bash
nuclei -u https://target.example -t brotli-request-decode-detect.yaml
# supply the real POST route if known (default candidates: /, /echo, /api, /)
nuclei -u https://target.example -t brotli-request-decode-detect.yaml -V path=/api/upload
```

In automation, run Nuclei with stdin closed (`< /dev/null`): with stdin
attached to an open pipe it was observed waiting on it and sending no
requests.

The template matches only on ACTIVE. A "finding" therefore means: *this URL
decodes Brotli request bodies; confirm the deployed Brotli version separately
before treating it as vulnerable.*

Python (3.9+, stdlib only - no pip packages required):

```bash
python3 brotli-request-decode-probe.py https://target.example/api
python3 brotli-request-decode-probe.py myhost.example:8443 /api/upload
python3 brotli-request-decode-probe.py --core --quiet myhost.example   # fewer requests, summary only
```

Run the script without arguments for all options.

## Validated behavior

Both tools were run against a 33-server reference lab covering Node,
Python, .NET, Java/Netty, Go, Envoy, nginx, and purpose-built adversarial
negatives (parse-skip on header, rate limiter, flaky backend, header echo,
lenient substring matcher, WAF fronted stacks):

The lab has 14 targets that decode Brotli request bodies and 19 that do not.
These results hold when the tools are given the lab's POST routes (`/echo`,
`/api`, `/`); with the Python probe's default paths (`/` and one random path)
only 4 of the 14 positives read ACTIVE - the other 10 read NO SIGNAL,
INCONCLUSIVE, or NOT ACTIVE, never a false answer.

- **No false positives observed.** None of the 19 non-decoding targets reached
  ACTIVE, for either tool, including the adversarial and WAF-fronted ones.
- Nuclei template: 13/14 lab positives detected on the `application/json`
  content type (the miss is a stack whose JSON parser refuses `br` while its
  form parser still decodes).
- brotli-request-decode-probe.py: 14/14 lab positives detected with the lab
  routes (it also probes `application/x-www-form-urlencoded`, which covers
  stacks whose JSON parser refuses encodings but whose form parser still
  decodes). The TLS-only target needs `--tls auto`, because an `http://` URL
  forces plain HTTP.

## Tested against

The methodology and both probes were validated against reference servers in
containers covering:

| Stack | Variants tested |
|---|---|
| Node.js / Express | Express 4, Express 5 (plain, route-level parser, dynamic bodies, auth gate, JSON-refuses-but-form-decodes) |
| Node.js (bare) | raw `http` module, no body parsing |
| Koa | koa-bodyparser |
| Fastify | plain, and with `@fastify/compress` request decompression |
| Python / aiohttp | with and without the `Brotli` package |
| .NET / ASP.NET Core | with the opt-in request-decompression middleware (gzip, deflate, br) |
| Java / Netty | plain, and with brotli4j |
| Go | net/http plain, net/http with brotli, fasthttp |
| Envoy | brotli decompressor filter, passthrough |
| nginx | passthrough, explicit br rejection (415), TLS-fronted Express |

Adversarial negatives were also tested: a server that skips parsing when a
`Content-Encoding` header is present, a rate limiter, a flaky backend, a
header-echo server, a lenient wire-bytes matcher, and WAF-fronted variants of
two of the above. None of these were ever reported ACTIVE.

## Known limits

Read these before drawing conclusions from a result:

- **Capability, not vulnerability.** ACTIVE does not mean the endpoint is
  exploitable or unpatched. It cannot distinguish Brotli 1.2.0 from 1.2.1:
  patched and unpatched decoders behave identically on valid input. Version
  confirmation requires out-of-band data (package inventories, SBOMs, runtime
  versions). Never report ACTIVE as "vulnerable".
- **Content type.** The Nuclei template probes `application/json` only. A
  stack that decodes `br` only for other content types (e.g. Express with
  `{ inflate: false }` on JSON but a form parser that still decodes) will read
  NO SIGNAL - a false negative, never a false positive. The Python probe
  covers `application/json` and `application/x-www-form-urlencoded`.
- **Reachable surface only.** The tools cannot see behind authentication
  (an auth gate reads NO SIGNAL, meaning "no answer", never "safe"), on
  routes they do not probe, or past a WAF that strips or blocks `br`.
- **Layer attribution.** If a front proxy (e.g. Envoy) decodes Brotli before
  an upstream that does not, the endpoint still reads ACTIVE; which layer
  decodes is not determinable remotely.
- **Path discovery.** The probes only try the paths you give them plus a
  small default list (`/`, `/echo`, `/api` in the template; `/` and one
  random path in the probes). Supplying real POST routes materially improves
  coverage; a decoder attached only to unknown routes will be missed.
- **Implementation fingerprinting.** The tools detect Brotli decoding, not
  which Brotli implementation is in use (Google's C decoder, Go's andybalholm
  port, etc.). They also cannot identify the library version.
- **Response stability.** Endpoints with rate limits, flaky backends, or
  highly dynamic response bodies can land INCONCLUSIVE or AMBIGUOUS; the
  tools choose "no answer" over guessing.
- **TLS.** The Python probe in `--tls auto` mode (the default for `host` and
  `host:port`) tries a TLS handshake first, then plain HTTP, and tries 443
  then 80 when no port is given; a `http://` or `https://` URL fixes the
  scheme. The Nuclei template tries TLS first on 443 and the usual TLS ports,
  and plain first on other explicit ports, then the other transport. A TLS
  port that answers plain HTTP with a server-specific error is handled, but
  exotic configurations (client certificates, mTLS-only listeners) may read
  NO RESPONSE.
- **Residual false-positive rate.** The guards make a false ACTIVE very
  unlikely, not impossible. In simulation, a server that answers 200 or 400 at
  random reached ACTIVE 3 times in 5,000 runs (0.06%), and a deliberately
  built deterministic server whose response depends only on a hash of the
  header and raw body did so about 6% of the time. Neither resembles a real
  stack, and none was seen in the lab, but treat ACTIVE as strong evidence to
  confirm, not proof.
- **One request burst at a time.** The tools make no attempt at concurrency,
  and sequential timing means a race window (e.g. a config change mid-probe)
  could produce inconsistent cells; the stability and reproduction guards
  turn those into non-answers rather than wrong verdicts.

## Tradeoffs made deliberately

- **False negatives over false positives.** Every ambiguous case degrades to
  AMBIGUOUS/INCONCLUSIVE/NO SIGNAL rather than ACTIVE.
- **No exploit-adjacent behavior.** No malformed stream, no decompression
  bomb, no oversized payload. This makes the tools safe to point at
  production infrastructure, at the cost of not confirming exploitability.
- **Behavior over version banners.** No reliance on `X-Powered-By` or
  component fingerprints, which are weak and spoofable signals.

## License

Apache License 2.0 - see `LICENSE`.

## What a typical session looks like

Every request in a session is a small `POST` to a path on the target. The
Python probe also sets `User-Agent: Python-urllib/<version>` (its HTTP
library's default) and `Accept-Encoding: identity`; the Nuclei template sets
`User-Agent: Mozilla/5.0 (compatible; brotli-capability-probe/1.0)`. The
request body is never larger than 65,536 bytes and, in practice, never
larger than 100 bytes.

Python probe, default run (2 paths x 2 content types): each cell starts with
the plain control pair, and most cells end there:

```
POST /echo
Content-Type: application/json

{"probe":1}                <- plain valid body (p_ok)

POST /echo
Content-Type: application/json

{"probe":                  <- plain invalid body (p_bad)
```

If the two plain responses differ, the Brotli cell follows. The Brotli bodies
are hand-built RFC 7932-valid streams (a stored/uncompressed meta-block, and a
decoy that wraps the invalid body while its raw bytes also embed the valid
one inside a metadata block decoders skip):

```
POST /echo
Content-Type: application/json
Content-Encoding: br

<15-byte Brotli stream decoding to {"probe":1}>      (b_ok)

POST /echo
Content-Type: application/json
Content-Encoding: br

<13-byte Brotli stream decoding to {"probe":>        (b_bad)

POST /echo
Content-Type: application/json
Content-Encoding: br

<26-byte decoy stream decoding to {"probe":,         (b_decoy)
 wire bytes containing {"probe":1}>

POST /echo
Content-Type: application/json

<the same 15-byte stream as b_ok, no header>        (n_ok)

POST /echo
Content-Type: application/json

{"probe":1}                <- stability repeat (p_ok2)
```

If these read ACTIVE, the same seven questions are asked once more in reverse
order to confirm reproduction. Only cells that reach a negative verdict add
the two annotation requests (a gzip-encoded body and an unknown
`Content-Encoding: xyz`), which only sharpen the negative explanation.

A decoder endpoint therefore sees: 2 plain requests, 5 Brotli requests, then
a 7-request reversed replay. A site that ignores request bodies sees only 2
plain requests per cell. No request ever carries a malformed or oversized
Brotli stream, an exploit payload, or anything except the bodies shown above.
