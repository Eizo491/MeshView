# Meshview 3D — Phase 1

Django project, data model, custom PCAP file reader, and custom protocol
dissectors (Ethernet, IPv4, TCP, UDP, DNS, HTTP). This is the foundation
the rest of the roadmap (live capture, the DRF API, the Three.js scene,
stats, encryption indicator, anomaly detection) builds on.

## What's here

```
manage.py
requirements.txt
meshview/                  Django project package
  settings.py                SQLite in WAL mode, installed apps, MESHVIEW_* settings
  urls.py
netcap/                     The one Django app (Phase 1 scope)
  models.py                  CaptureSession, Packet, Host, Conversation
  admin.py                   Registered so you can browse imported data at /admin/
  dissectors/
    ethernet.py               Ethernet II (+ single 802.1Q tag)
    ip.py                      IPv4 header (IPv6 out of scope, see Limitations)
    tcp.py                     TCP header incl. flags
    udp.py                     UDP header
    dns.py                     DNS header + question section, with name-compression pointers
    http.py                    HTTP/1.x request/response line + headers
    pipeline.py                Chains the above into one DissectedPacket per frame
  pcap/
    reader.py                  From-scratch classic-pcap (.pcap) file format reader
    importer.py                Reads a .pcap, runs the pipeline, bulk-writes in batches,
                                maintains Host/Conversation aggregates
  management/commands/
    import_pcap.py             CLI: import a .pcap into a new CaptureSession
sample_pcaps/
  make_sample.py               Builds a tiny synthetic .pcap (DNS query + HTTP GET)
                                with no external dependencies, for testing without
                                a real capture file
```

## Setup

```bash
python -m venv venv
source venv/bin/activate        # venv\Scripts\activate on Windows
pip install -r requirements.txt
python manage.py migrate
```

## Try it

```bash
# Build a tiny test capture (or point at a real .pcap you already have)
python sample_pcaps/make_sample.py

# Import it
python manage.py import_pcap sample_pcaps/sample.pcap --name "test session"

# Browse the decoded packets
python manage.py createsuperuser
python manage.py runserver
# then open http://127.0.0.1:8000/admin/
```

Or inspect it straight from the shell:

```bash
python manage.py shell -c "
from netcap.models import Packet
for p in Packet.objects.all():
    print(p.protocol, p.src_ip, p.dst_ip, p.info)
"
```

## Design notes worth knowing before Phase 2+

- **Custom dissectors, not scapy.** `netcap/dissectors/*.py` parse raw
  bytes with `struct` directly. Per the spec, scapy is reserved for
  *capturing* live traffic (Phase 4) — it is never used to decode
  anything here, including PCAP files, which get their own from-scratch
  reader (`pcap/reader.py`).
- **One pipeline, two sources.** `dissectors/pipeline.dissect_packet()`
  takes raw frame bytes + a timestamp and returns a `DissectedPacket`.
  The PCAP importer calls it once per record; the live-capture command
  in Phase 4 will call the exact same function per sniffed frame. That's
  what makes "the rest of the system doesn't care where the data came
  from" (spec section 5) literally true rather than aspirational.
- **Never raises past the pipeline.** `dissect_packet` catches
  `DissectionError` at each layer and falls back to whatever the
  earlier, successfully-parsed layers found, recording `parse_error`.
  A malformed packet becomes a partially-decoded row, not a crashed
  import — matters a lot for real-world PCAPs with truncated frames.
- **Batched writes.** The importer buffers `Packet` rows and
  `bulk_create`s every `MESHVIEW_BATCH_SIZE` (default 500, see
  `settings.py`) rather than one INSERT per packet. Host/Conversation
  aggregates are accumulated in memory during the import and
  upserted once at the end.
- **Payload previews only.** Per the ethics/safety section, packets
  store a short printable-ASCII preview (`MESHVIEW_PAYLOAD_PREVIEW_BYTES`,
  default 64), not full payload contents.
- **Known Phase-1 limitations** (also listed in spec section 11):
  IPv4 only, no reassembly of HTTP messages split across multiple TCP
  segments, DNS answer *records* aren't parsed yet (only the question
  section — answers are next once the stats/3D layers need them), and
  the plaintext/encrypted classification (section 9) is a fixed
  port table, not protocol inspection.

## What's tested

`sample_pcaps/make_sample.py` builds a real classic-pcap file (correct
magic number, header, per-packet records) containing a DNS query and an
HTTP GET over TCP, entirely with `struct` — no scapy/dpkt involved, so
it doubles as a check that the reader and dissectors agree with each
other independent of any third-party pcap library. Importing it via
`manage.py import_pcap` decodes all 3 frames with zero parse errors,
correctly classifies one as DNS (question: `example.com`) and one as
HTTP (`GET /index.html`), and produces correct Host/Conversation
aggregates. DNS name-compression pointers were separately verified
against a synthetic message with a pointer partway through a name.

## Next (Phase 2)

Packet table + filters (`ip`, `port`, `protocol`) + details pane, and
DRF endpoints in `netcap/urls.py` (currently an empty placeholder) so
the frontend has something to call.

---

# Phase 2 — packet table, filters, details pane, DRF API

Adds a browsable API and a working (non-3D) web page on top of Phase 1.

## New in this phase

```
netcap/
  serializers.py     CaptureSession, Packet (list + detail variants), Host,
                      Conversation, and a PCAP upload serializer
  api_views.py        DRF ViewSets/APIView backing the endpoints below
  api_urls.py          DRF router, mounted at /api/
  views.py             Django view that renders the page shell
templates/netcap/
  base.html             Shared layout + design tokens
  packets.html          Session picker, upload button, filter bar, packet
                         table, and a details pane -- all wired up with
                         plain JS calling the API below
```

## API endpoints (mounted at `/api/`)

| Endpoint | Notes |
|---|---|
| `GET /api/sessions/` | List capture sessions, each with a `packet_count` |
| `GET /api/sessions/<id>/` | One session |
| `GET /api/sessions/<id>/hosts/` | Host aggregate rows for that session |
| `GET /api/sessions/<id>/conversations/` | Conversation aggregate rows |
| `GET /api/packets/?session=<id>` | Packet table. Also accepts `protocol`, `ip` (matches src or dst), `port` (matches src or dst), `encrypted` (`true`/`false`), `anomaly` (`true`/`false`), `q` (substring match on `info`) |
| `GET /api/packets/<id>/` | Full packet details (details-pane payload) |
| `POST /api/pcap-uploads/` | Multipart upload, field `file` (must end in `.pcap`) + optional `name`; imports it and returns the new session |

Pagination is DRF's default `PageNumberPagination`, 200 per page
(`MESHVIEW` settings aren't involved here; see `REST_FRAMEWORK` in
`settings.py` to change it).

## Try it

```bash
python manage.py runserver
```

Open `http://127.0.0.1:8000/` — upload a `.pcap` (or import one via
`manage.py import_pcap` first and just pick it from the session
dropdown), then use the filter bar and click a row to open the details
pane. The browsable DRF API is also just there in a browser at
`http://127.0.0.1:8000/api/packets/?session=1`.

## Design notes

- **Two Packet serializers on purpose.** `PacketListSerializer` only
  carries the table's columns; `PacketDetailSerializer` is `fields =
  "__all__"`. A session with tens of thousands of packets would make
  the table endpoint slow and bloated if every row carried MAC
  addresses and payload previews it doesn't display.
- **Filtering is hand-rolled, not django-filter.** Given the small,
  fixed set of filters spec section 4 actually asks for (ip, port,
  protocol), `PacketViewSet.get_queryset()` reads query params
  directly rather than pulling in another dependency.
- **The upload endpoint reuses the Phase 1 importer as-is.** It writes
  the upload to a temp file and calls `import_pcap_file()` — the same
  function the `import_pcap` management command calls — so there's
  exactly one code path for "a pcap became a CaptureSession," whether
  it arrived over HTTP or the CLI.
- **The page is plain HTML/JS, not React.** Matches the stack in spec
  section 6 (HTML/CSS/JS + Three.js); the same vanilla-JS approach is
  what the 3D scene in Phase 3 will sit alongside.

## What's tested

Verified via Django's test client (equivalent to hitting a running
server): session list, packet list, filtering by `protocol`, `port`,
and `ip` each return the expected subset, packet detail returns full
fields, host/conversation aggregate endpoints return correct rolled-up
figures, the page renders without template errors, and the upload
endpoint both successfully imports a valid `.pcap` (201, correct
packet/byte counts) and rejects a non-`.pcap` file (400) via its
serializer validation.

## Known Phase 2 limitations

- No auth on the API or upload endpoint — fine for local/dev use,
  not for anything exposed beyond your own machine.
- The packet table polls nothing and has no live updates yet; that
  arrives with live capture (Phase 4), likely over WebSocket
  (Django Channels, listed as a bonus in spec section 4).
- No stats dashboard yet (protocol breakdown, top talkers) — that's
  Phase 5 per the spec's suggested timeline, though the `hosts` and
  `conversations` endpoints added here are what it'll be built on.

## Next (Phase 3)

The Three.js 3D scene: nodes per host sized by traffic, links per
conversation, particles for packets, colored by protocol — fed by the
same `/api/sessions/<id>/hosts/` and `/conversations/` endpoints this
phase just added.

---

# Phase 3 — the 3D network graph

Adds the Three.js scene described in spec section 8, as a second tab
next to the packet table (`/scene/`), sharing the same session
selector.

## New in this phase

```
netcap/views.py        + SceneView (page shell, same pattern as PacketTableView)
netcap/urls.py          + "scene/" route
templates/netcap/
  base.html               + a nav bar so you can switch Packet Table <-> 3D View
  scene.html              The 3D scene itself
```

Nothing changed in the API — the scene is built entirely from the
`GET /api/sessions/<id>/hosts/` and `GET /api/sessions/<id>/conversations/`
endpoints Phase 2 already exposes. `Host.is_local` (set during PCAP
import for any RFC1918/private address) is what lets the scene
highlight your own machine at the center, per spec section 8.

## What it does

- **Nodes** — one sphere per host. Size is on a log scale of that
  host's byte count (so one heavy talker doesn't dwarf everything
  else). The local/private-range host is pinned at the origin and
  colored teal; everyone else starts on a ring around it and a small
  hand-rolled force simulation (repel + spring + a gentle pull to
  center) spreads them out in real time.
- **Links** — one thin cylinder per conversation, colored by protocol
  (DNS blue, HTTP green, HTTPS/TLS purple — a plaintext-port `TCP`
  conversation gets reclassified to the HTTPS color if `encrypted` is
  true, everything else amber/gray), thickness scaled to that
  conversation's byte count.
- **Particles** — a single reused pool of 240 small spheres (spec
  section 8's "capped at a few hundred at once"). Each active
  conversation spawns particles that travel from source to
  destination at a rate weighted by that conversation's traffic share,
  so heavier conversations look busier. This is a traffic-volume
  visualization, **not real-time packet replay** — that's the
  timeline feature in Phase 5, once live capture exists.
- **Interaction** — orbit/zoom via `OrbitControls`, hover shows a
  tooltip (host or conversation summary), click a node or link to
  populate the details panel on the right with the full aggregate
  record. Picking is done by raycasting directly against the node and
  link meshes.
- **Filter** — the protocol dropdown dims (not hides) every
  non-matching link and stops spawning new particles on it, per spec
  section 8's "filters that dim non-matching traffic."

## Try it

```bash
python manage.py runserver
```
Open `http://127.0.0.1:8000/`, import a `.pcap` if you haven't, then
click **3D View** in the top nav (or go straight to `/scene/`). The
session you pick is kept in the URL query string so switching tabs
keeps the same session selected.

## Design notes / known limitations

- **Three.js loads from a CDN via an import map** (`unpkg.com`), as
  plain ES modules — this is a page your own Django dev server serves
  to your own browser, not a sandboxed artifact, so there's no
  restriction on which CDN or module system to use here.
- **The force layout is hand-rolled**, not d3-force or a physics
  library — a few dozen lines of repulsion/spring/centering, run every
  frame. It's tuned to look reasonable for capture sizes in the tens
  to low hundreds of hosts; if you throw a capture with thousands of
  distinct hosts at it, expect it to look cluttered and possibly
  chug — that's a real scaling limit worth knowing about, not a bug
  waiting to be found.
- **I could not test the WebGL rendering itself in this environment**
  (no browser/GPU here) — I verified the page renders server-side with
  no template errors and syntax-checked the embedded JavaScript with
  Node, but the actual visual result (does the layout look right, do
  particles move smoothly, does picking feel responsive) needs your
  eyes in a real browser. Please try it and tell me what's off; that's
  normal for this kind of feature and much easier to fix once you can
  point at what looks wrong.
- **Anomaly red** (from the legend) isn't wired to anything, since
  Phase 6 (anomaly detection) doesn't exist yet — it's shown as a
  preview of what's coming.

## Next (Phase 4)

Live capture (Npcap + a management command run as admin) feeding the
exact same `dissect_packet` pipeline as the PCAP importer, streaming
into the same `hosts`/`conversations`/`packets` this phase already
knows how to display — plus the rolling ~60s window the spec calls
for.

---

# Phase 4 — live capture, rolling window, WebSocket push

Adds a `capture_live` management command that sniffs real traffic via
Npcap (Windows) / libpcap (Linux/Mac) through scapy, decodes it with
the exact same pipeline the PCAP importer uses, and streams it into a
live `CaptureSession` that the scene can watch update in real time.

## New in this phase

```
netcap/capture/
  engine.py       LiveCaptureEngine -- batching, the rolling ~60s
                  window (prune + full aggregate recompute per flush),
                  and an on_flush hook. No scapy/OS dependency at all.
  interfaces.py   Formats scapy's interface objects into the friendly
                  name / IPv4 / description table --list-interfaces
                  prints. No scapy import, so it's unit-testable.
netcap/snapshot.py      build_scene_snapshot() -- a session's current
                         hosts + conversations, straight from the DB
netcap/consumers.py     SceneConsumer -- one instance per browser tab
                         watching a session; sends the current state on
                         connect, then again whenever the DB changes
netcap/routing.py       ws/scene/<session_id>/ -> SceneConsumer
netcap/management/commands/
  capture_live.py       The scapy/Npcap adapter itself: turns sniffed
                         frames into (raw bytes, timestamp) calls into
                         LiveCaptureEngine, and Ctrl+C into a clean stop.
netcap/tests/
  frames.py                    struct-built synthetic Ethernet frames
                                (same approach as sample_pcaps/make_sample.py)
  test_capture_engine.py       batching, rolling-window pruning, aggregate
                                recompute, pipeline-parity -- 8 tests
  test_live_push.py            SceneConsumer via Channels'
                                WebsocketCommunicator -- 8 tests
  test_list_interfaces.py      interface table, with Windows-shaped
                                fakes -- 7 tests
meshview/asgi.py        now a ProtocolTypeRouter (http + websocket)
meshview/settings.py    + "daphne" (first in INSTALLED_APPS, so plain
                          runserver serves WebSockets), "channels",
                          MESHVIEW_LIVE_WINDOW_SECONDS (60)
templates/netcap/scene.html
                         opens ws://.../ws/scene/<id>/ for a live,
                          still-capturing session and merges each
                          message into the scene in place
```

## Try it

```bash
pip install -r requirements.txt   # now includes scapy, channels, daphne

# See what scapy can capture on: friendly name, IPv4, adapter description.
# Pass the NAME column to --iface. (--all also shows interfaces scapy
# considers unusable: no IP/MAC, or no matching Npcap device.)
python manage.py capture_live --list-interfaces

# Windows: run this shell as Administrator
python manage.py capture_live --iface "Ethernet"

# Linux/Mac: needs elevated privileges to open a raw socket
sudo python manage.py capture_live --iface eth0 --bpf "tcp or udp"
```

While it's running, start the web server in a **second terminal**
(`python manage.py runserver` -- this now serves WebSockets too) and open
the scene URL `capture_live` prints. Hosts and conversations update on
their own as traffic flows; anything older than the window (60s by
default) disappears from the DB and the scene. The toolbar shows
`live` / `reconnecting…` / `capture ended`.

Start `capture_live` first, then open the scene URL it prints: the
session dropdown is filled when the page loads, so a capture started
*after* the page was opened won't be in it until you reload once.

## Design notes

- **Same pipeline, still true.** `capture_live` calls
  `LiveCaptureEngine.handle_frame(raw, timestamp)`, which calls
  `dissect_packet()` — the identical function the PCAP importer calls.
  `test_capture_engine.py` asserts this directly (decoding a frame
  through the engine and through `dissect_packet` head-on produces the
  same protocol/info/IPs), so "one pipeline, two sources" isn't just a
  comment anymore, it's a test.
- **The engine doesn't know scapy exists.** `LiveCaptureEngine` takes
  raw bytes + a timestamp and nothing else — `capture_live.py` is the
  only file that imports scapy, and it imports it lazily inside
  `handle()` so the rest of the app doesn't break if scapy/Npcap isn't
  installed. That split is what let the rolling-window logic (the part
  with the most room for an off-by-one) get fully unit-tested here,
  in an environment with no NIC and no way to install Npcap at all.
- **The rolling window is a full recompute, not incremental
  bookkeeping.** Every flush (every ~0.5s, or sooner at
  `MESHVIEW_BATCH_SIZE` packets), the engine deletes `Packet` rows
  older than the window and rebuilds `Host`/`Conversation` from
  scratch off whatever's left, rather than trying to subtract expired
  packets from running totals. Simpler, and it can't drift out of sync
  with what just got deleted. At the same "tens to low hundreds of
  hosts" scale Phase 3's force layout already assumes for a single
  capture window, a full scan every half second is cheap; a much
  busier interface (thousands of hosts in 60s) would need this to
  become incremental — a real scaling limit worth knowing about, same
  spirit as Phase 3's force-layout note.
- **Live updates cross a process boundary, so they go through the
  database.** `capture_live` and the web server are two separate OS
  processes. The first version of this phase pushed updates with a
  Channels `group_send` over `InMemoryChannelLayer`, which only exists
  inside one process — a push from the capture process never reached a
  socket held by the server process. Its tests passed because they ran
  both halves in one process; a three-process check (server, a separate
  process running the real engine, a real WebSocket client) showed the
  client receiving nothing. `SceneConsumer` now reads the session's
  hosts/conversations from SQLite on connect and every 0.5s (the same
  interval as the engine's flush), sending only when something changed,
  and stops once the session is no longer active. SQLite's WAL mode lets
  that reader run alongside the capture writer. `channels_redis` would
  also work but needs a Redis server, which is awkward on Windows.
- **The scene merges updates instead of rebuilding.** `scene.html`
  routes both the first REST load and every WebSocket message through one
  `applySnapshot()`: existing hosts keep their position (so the force
  layout doesn't restart every half second), new ones spawn on the outer
  shell, and hosts/conversations that fell out of the rolling window are
  removed. Node size and link thickness are set through `mesh.scale` on
  shared geometry so they can change in place.
- **What has and hasn't been verified.**
  - Verified without a NIC: the rolling-window engine (synthetic
    frames); the consumer (Channels' `WebsocketCommunicator`); the
    interface table (fakes shaped like Windows adapters, plus real scapy
    on Linux); and the cross-process path end to end — a server process,
    a separate process running the real `LiveCaptureEngine`, and a real
    WebSocket client, which saw the initial state, a host appear, hosts
    age out of a 3-second window, and `is_active: false` at the end.
  - Verified for `scene.html` without a browser: its script was run under
    Node against the real three.js (only the WebGL renderer and
    OrbitControls stubbed) with a fake WebSocket — merge, removal,
    selection refresh, stale-socket handling, back-off reconnect and
    capture-ended handling. That doesn't cover how it *looks*: whether
    nodes settle nicely as hosts come and go, or whether the status
    indicator sits well, needs your eyes.
  - Still only exercised on your machine: `sniff()` on a real interface
    under Npcap, and `--list-interfaces` on real Windows adapters (the
    format was tested against Windows-shaped fakes, not a real Windows
    scapy).

## Known Phase 4 limitations

- **No packet-level detail over the socket, only aggregates.** The
  payload is hosts + conversations (what the 3D scene needs); the packet
  table doesn't live-update from it. Extending `build_scene_snapshot` to
  include recent `Packet` rows is straightforward if the table needs the
  same treatment.
- **The consumer polls the DB per open tab** (2 small queries every
  0.5s, only while a live session is still capturing). Trivial for one
  person on one machine; it's the thing to replace (Redis + group_send)
  if this ever serves many viewers.
- **Every private/loopback IP is marked `is_local`** (Phase 3's heuristic)
  and pinned at the scene's center. On a real LAN capture that stacks the
  router, other devices and this machine on top of each other. Marking
  only the capture interface's own IP (which `--list-interfaces` now
  knows) would fix it; not done yet.
- **One capture at a time.** Nothing stops you running `capture_live`
  twice, but SQLite's single-writer model means two concurrent live
  sessions on one machine will contend rather than run cleanly in
  parallel.

## Next (Phase 5, per the original roadmap)

Stats dashboard (protocol breakdown, top talkers) off the
`hosts`/`conversations` endpoints, real-time packet-replay in the
scene using live capture rather than the traffic-volume approximation
Phase 3 built, and the encrypt/decrypt demo panel.

---

# UI refresh

A visual pass over `base.html`, `packets.html`, and `scene.html` —
no backend or data-model changes, and no changes to the tested Phase 4
capture/WebSocket logic.

## What changed

- **Real fonts.** IBM Plex Sans/Mono were referenced in the CSS from
  Phase 2 onward but never actually loaded — the app was silently
  falling back to system fonts the whole time. Now loaded via Google
  Fonts in `base.html`.
- **Emoji glyphs replaced with inline SVG icons.** The encrypted/
  plaintext lock and the anomaly warning triangle in the packet table
  were Unicode emoji (`&#128274;`, `&#128275;`, `&#9888;`), which
  render inconsistently across platforms/fonts. They're now `currentColor`
  SVGs that inherit the theme properly and animate (the anomaly icon
  gets a soft pulse).
- **A real header.** Sticky, blurred backdrop, a small animated logo
  mark (two pulsing rings around a dot — literally the "node with
  traffic" idea from spec section 8, in miniature), and a pill-style
  nav where the active tab is a sliding highlight rather than a static
  border.
- **Motion with a purpose, not decoration for its own sake:**
  - A slow, subtle ambient gradient drift behind the whole page
    (`prefers-reduced-motion` disables it, like everything else
    animated here).
  - Page content fades/rises in on load; table rows cascade in with a
    tiny stagger; the details panel fades in on selection.
  - The live-capture status dot (`scene.html`) now actually pulses
    when `state="live"` and blinks while connecting/reconnecting —
    before this it just changed color with no motion at all, which is
    an easy thing to miss out of the corner of your eye.
  - Buttons lift slightly on hover and settle on click; inputs get a
    proper focus ring instead of the browser default.
  - Added `.spinner` and `.skeleton` primitives to `base.html` and put
    the spinner to use in the upload control, which previously only
    ever showed a plain text string with no feedback while a large
    `.pcap` was still uploading.
- **Small consistency fixes:** matching padding/`border-radius` scale
  and sticky-panel offsets between the packet table and 3D view, which
  had drifted slightly apart across phases.

## Verified

- `manage.py check` and the full test suite (23 tests) still pass
  unchanged — this was a template/CSS-only pass.
- Both pages were rendered through Django's test client after the
  change: `200` on `/` and `/scene/`, and scanned for any character in
  the Unicode emoji ranges — none remain.
- The importer and `--list-interfaces` were re-run end-to-end after
  the change to confirm nothing in the surrounding files was disturbed.

## What I couldn't verify here

Same limitation as Phase 3/4: no browser/GPU in this environment, so
the animations, blur backdrop, and font loading need your eyes to
confirm they actually look right and perform smoothly — particularly
the ambient background drift and the row-cascade animation on a large
packet table, which are the two effects most likely to need tuning
(intensity, timing) once you can see them.

---

# Live capture control panel, pagination fix, auto-refresh

## The "Next" button bug

**Root cause:** the packet table's pagination stored DRF's `next`/
`previous` links verbatim (absolute URLs like
`http://127.0.0.1:8000/api/packets/?page=2&session=1`, built
server-side via `request.build_absolute_uri()`) and fetched those
directly. Any mismatch between the host Django thinks it's serving on
and the origin the browser actually loaded the page from -- `localhost`
vs `127.0.0.1`, a different port, a proxy -- makes that `fetch()` fail,
and with no error handling, the table just silently stopped updating,
which is what "it disappears" was.

**Fix:** the frontend now tracks a plain page *number* (`state.page`)
and builds every request itself from `${API}/packets/?...&page=N`,
never touching DRF's absolute links for navigation (they're still
used, but only to decide whether Prev/Next should be disabled).
This can't drift from the page's actual origin. `loadPackets()` also
now has real error handling — a failed request shows a message in the
table instead of leaving stale state with no explanation.

## Live capture control panel

You can now start and stop a capture from the browser instead of only
`manage.py capture_live` in a terminal — a new bar above the packet
table:

- **Interface dropdown**, populated from `GET /api/capture/interfaces/`
  (the same friendly-name/IP listing `--list-interfaces` prints)
- **Optional BPF filter** field (e.g. `tcp port 443`)
- **Start/Stop** buttons calling `POST /api/capture/start/` and
  `POST /api/capture/stop/`
- A live status pill and inline error display if the capture fails
  (bad interface, permission denied, etc.)

**This still needs elevated privileges to actually capture anything**
-- the note is shown directly in the UI, not just here. The important
difference from the CLI: starting capture from the browser runs it in
a background thread *inside the Django server process*, so now the
**server itself** needs to run elevated (Administrator / root) for as
long as it's running, rather than just a throwaway terminal for one
capture's duration. See `netcap/capture/manager.py`'s docstring for
the full reasoning. Use whichever fits your situation better; both
paths write to the same `CaptureSession`/`Packet`/`Host`/`Conversation`
tables and show up identically everywhere in the UI.

## Auto-refresh (Wireshark-style "follow the capture")

The packet table now has an **Auto-refresh** checkbox, shown whenever
the selected session is currently active (`is_active`) — whether that
capture was started from this browser or from a separate
`capture_live` terminal, it doesn't matter, both are just "an active
CaptureSession" from the API's point of view.

While checked and parked on page 1, the table quietly re-fetches every
1.5 seconds. Two deliberate choices behind how this behaves:

- **Newest-first while live.** A live/rolling-window session requests
  `ordering=-timestamp` instead of the usual chronological order, so
  "page 1" is always "what just happened" — closer to Wireshark's
  auto-scroll-to-bottom than making you flip forward through pages as
  the window fills. A finished/imported session keeps the original
  chronological order, which reads better for after-the-fact review.
- **Only refreshes on page 1.** If you've clicked into an older page
  to inspect something mid-capture, auto-refresh backs off rather than
  yanking your place out from under you every couple of seconds — it
  resumes the moment you're back on page 1 (or you can uncheck it
  entirely).

## Verified

- All 37 tests pass unchanged.
- Reproduced the exact pagination bug scenario (450 packets across 3
  pages) and confirmed each page now returns distinct rows through the
  new page-number-based fetch.
- Confirmed `ordering=-timestamp` correctly returns the newest packet
  first for a live session.
- Exercised `/api/capture/*` end-to-end via Django's test client,
  including real scapy failing fast on a nonexistent interface name
  and the error surfacing cleanly instead of hanging.
- Page renders with no template errors; embedded JS passes a Node
  syntax check.

## What I couldn't verify here

No browser in this environment, so the actual UX of starting a
capture, watching the status pill and packet counts update, and the
auto-refresh cadence feeling smooth (not janky, not too slow) all need
your eyes on your machine — ideally with the elevated `runserver` setup
so a real capture is actually flowing while you watch it.
