# Local pairing bridge

LocalDevVPN can act as the native half of a web-based iOS signer: it runs the
device pairing flow, keeps the resulting pairing record on the device, and hands
that record to a local web client **only after the user approves the request in
the app**.

Safari cannot pair a device, and a web page cannot reach `lockdownd`. This bridge
is the smallest native surface that closes that gap without turning LocalDevVPN
into a signing tool itself.

```
website ──▶ localdevvpn://pair ──▶ LocalDevVPN ──▶ user approves in-app
   ▲                                    │
   └──── access token (URL fragment) ◀───┘
   │
   └──▶ http://127.0.0.1:<port>/v1/pairing-record  (Bearer <token>)
```

## Where it plugs in

LocalDevVPN already had two ways for the outside world to talk to it:

* the `localdevvpn://` URL scheme (`enable`, `disable`, with a `scheme=`
  callback), handled in `LocalDevVPNApp.handleURL(_:)`;
* the `ControlLocalDevVPNIntent` App Intent.

Both are one-shot, fire-and-forget commands: they can start the tunnel but cannot
return data. The bridge extends the URL scheme with a third verb, `pair`, and
adds the missing return path as a loopback HTTP server. Nothing else about the
app's networking changed — the packet tunnel and the bridge are independent, and
the bridge is bound to `127.0.0.1`, which is not routed through the tunnel.

| File | Role |
| --- | --- |
| `LocalDevVPN/Pairing/PairingRecord.swift` | Record model, validation, on-device storage |
| `LocalDevVPN/Pairing/DevicePairingService.swift` | Pairing flow, provider seam, flow state |
| `LocalDevVPN/Pairing/PairingBridge.swift` | Sessions, authorization, routing |
| `LocalDevVPN/Pairing/PairingHTTPServer.swift` | Loopback-only HTTP/1.1 server |
| `LocalDevVPN/Pairing/PairingBridgeViews.swift` | Settings section, authorization prompt |

## Turning it on

The bridge is **off by default**. No socket is opened until the user enables
*Settings → Pairing Bridge → Allow local web clients*, or follows a
`localdevvpn://pair` link, which enables it as part of the request.

It listens on the first free port of `19842`, `19843`, `19844`. A client finds it
by probing them in order with `GET /v1/status`.

## Authorization model

The requirement that drove the design: `GET /pairing-record` must never answer a
random page that probes loopback.

1. **Every request needs `X-LocalDevVPN-Client`.** That header is not
   CORS-safelisted, so a cross-origin caller is forced through a preflight and
   cannot fire a "simple" request at the bridge.
2. **`Host` must be `127.0.0.1` or `localhost`.** A page that reaches the bridge
   through a hostname that resolves to loopback (DNS rebinding) sends that
   hostname and is rejected.
3. **The record needs a session the user approved in the app.** Creating a
   session only raises a prompt; it grants nothing. The prompt shows the origin
   (from the `Origin` header, which a page cannot forge) and a six-digit code that
   the requesting page must display, so the user confirms the tab in front of
   them rather than a hidden one.
4. **Access tokens are 256-bit, random, in memory only,** compared in constant
   time, and never written to disk. Approvals last 15 minutes; unanswered prompts
   expire after 2 minutes; session creation is rate-limited to 5/minute and one
   prompt at a time.
5. **The record itself never leaves the device.** It is written to the app
   container with complete data protection, excluded from backups, and served
   only over loopback. LocalDevVPN makes no outbound connections with it, and it
   is never put in a URL, a log line or an analytics event — logs carry only a
   truncated SHA-256 fingerprint.
6. **Credentials are never allowed.** `Access-Control-Allow-Credentials` is not
   sent, so browsers never attach ambient cookies to bridge requests.

Revoking is immediate: *Revoke All Access* in Settings, turning the bridge off,
or backgrounding the app.

## Flows

### A. Deep link (works when the user is on the site)

Best flow on iOS, because a page in Safari cannot reach a suspended app.

1. Site opens
   `localdevvpn://pair?client=My%20Signer&callback=https%3A%2F%2Fsigner.example%2Fresume&state=abc123`.
2. LocalDevVPN comes to the front, enables the bridge, and shows the prompt.
3. On approval it opens the callback with the result in the **fragment**, so the
   token never reaches the site's server or its access logs:
   `https://signer.example/resume#ldv_token=…&ldv_session=…&ldv_port=19842&ldv_api=1&ldv_state=abc123`.
4. Safari returns to the page, which now calls the bridge with
   `Authorization: Bearer <ldv_token>`.

`callback` must be `https:`, or `http:` on a loopback host; anything else is
rejected so the token cannot be handed to an arbitrary app or scheme.

### B. Poll (works when the app is on screen — iPad Split View, or the user switches back)

1. `POST /v1/sessions` → `201` with `session_id` and `verification_code`.
2. The page shows the code; the user approves the matching code in LocalDevVPN.
3. The page polls `GET /v1/sessions/{id}` until `state` is `authorized`, which
   also returns the `access_token`.

## API

Base URL `http://127.0.0.1:<port>`, JSON in and out, `X-LocalDevVPN-Client:
<name>` required on every request.

### `GET /v1/status` — anonymous

```json
{
  "api": 1,
  "app": "LocalDevVPN",
  "version": "1.2.1",
  "authorization_required": true,
  "client_header": "X-LocalDevVPN-Client",
  "tunnel": { "status": "connected", "interface_ip": "10.7.1.1/32", "device_ip": "10.7.0.1/32" },
  "pairing": { "system_flow_available": false, "mechanism": "…", "reason": "…" },
  "record": { "available": true }
}
```

Deliberately says only *whether* a record exists — no fingerprint, no contents.

### `POST /v1/sessions` — anonymous, raises the prompt

```json
{ "client": "My Web Signer", "origin": "https://signer.example" }
```

`201` → `{ "session_id", "state": "pending_authorization", "verification_code",
"expires_in", "poll_after_ms" }`. `409 authorization_pending` if a prompt is
already up, `429 rate_limited` past 5 requests/minute.

The `origin` field in the body is only a fallback for display and is shown as
unverified; the `Origin` header wins when present.

### `GET /v1/sessions/{id}`

`{ "state": "pending_authorization" | "authorized" | "denied" | "revoked", … }`.
Once authorized it also carries `access_token`, `pairing` (the flow state) and
`record` (`available`, `fingerprint`).

### `DELETE /v1/sessions/{id}` — `204`, drops the session

### `POST /v1/sessions/{id}/pairing` — Bearer

Starts the pairing flow. `202` with the session body; poll the session for
`pairing.state`:

| state | meaning |
| --- | --- |
| `idle` | nothing running |
| `in_progress` | the system flow is working |
| `awaiting_user_action` | the user has to do something; `message` says what, `code` carries a PIN when the OS shows one |
| `completed` | a record is stored |
| `failed` / `unavailable` | `message` says why |

### `GET /v1/pairing-record` — Bearer

JSON by default:

```json
{ "format": "plist", "encoding": "base64", "data": "…", "fingerprint": "…", "host_id": "…" }
```

Send `Accept: application/x-plist` for the raw plist bytes. `409 no_pairing_record`
when there is nothing to hand over, `401` without a valid token.

### `POST /v1/tunnel` — Bearer

`{ "action": "start" | "stop" | "status" }` → the tunnel status and the configured
addresses. A signer needs the tunnel up before it can reach the device, and this
saves it from bouncing the user through `localdevvpn://enable`.

## Limitations found while building this

### iOS pairing APIs — the important one

**There is no public API for an app to create a lockdown pairing record for the
device it runs on.** Both mechanisms that mint one are closed to third-party apps:

* **iOS ≤ 16 — lockdown pairing.** A *host* sends `lockdownd` a `Pair` request
  over usbmux (USB or the wireless equivalent) and the device raises "Trust This
  Computer?". The request has to come from outside the sandbox; an app cannot
  reach `com.apple.mobile.lockdown` for its own device.
* **iOS 17+ — remote pairing (RemoteXPC).** The six-digit PIN flow Xcode uses for
  wireless pairing is served by `remotepairingd` behind
  `com.apple.internal.dt.remote.pairing`, an Apple-internal entitlement. It is
  not issuable to third-party developers, and an app using it would not pass App
  Review.
* **`DeviceDiscoveryUI`** is the one public "system pairing UI with a PIN", but it
  pairs an app with an Apple TV/Vision Pro *application service* and yields an
  `NWEndpoint` — not a lockdown pairing record. It does not help here.

So `SystemPairingFlowProvider` reports its availability honestly instead of
shipping a private-API path, and the shipped flow falls back to a user-driven
import of a pairing file (produced by `jitterbugpair`, `idevicepair`, AltServer,
SideStore…) through the system document picker. The import is real, App
Store-safe, and works on every supported iOS version.

The seam is deliberate: a build that carries the entitlements can compile a real
implementation in behind `-D LOCALDEVVPN_NATIVE_PAIRING` (a `NativePairingFlow`
with the same two entry points) and every other layer — states, endpoints,
authorization, UI — keeps working unchanged, including `awaiting_user_action`
with a `code`, which is exactly the shape a PIN flow needs.

### Entitlements

None added. Loopback listeners need no entitlement, and `127.0.0.1` is exempt
from the local-network privacy prompt, so no `NSLocalNetworkUsageDescription` is
required (the existing `NSBonjourServices` entry is unrelated to the bridge). The
app keeps exactly the two networking entitlements it already had.

### App Store

* A loopback HTTP server in a foreground app is fine; several shipping developer
  tools do it.
* The private pairing services above are not, which is why they are not used.
* Because the record is user-supplied or user-approved and never transmitted, the
  app's "no data collected" posture is unchanged.

### Background execution

**This is the sharpest practical limit.** iOS suspends the app shortly after it
leaves the screen, and a suspended app's listener refuses connections. The bridge
therefore:

* stops the listener when the app is backgrounded, and restarts it on return;
* holds a `beginBackgroundTask` assertion for up to ~25 s first, so a page that
  was just handed a token in flow A can still fetch the record after Safari comes
  forward;
* drops any pending authorization prompt on backgrounding, since nobody can
  answer it.

Practical consequences for a web signer: fetch what you need immediately after
the callback, do not assume the bridge answers minutes later, and treat a
connection failure as "ask the user to reopen LocalDevVPN" rather than an error.
There is no way around this with public API — background listeners require a
`NEAppPushProvider`-class entitlement that does not apply here.

### Safari / CORS

* Preflights are answered for `GET`, `POST`, `DELETE`; `Authorization`,
  `Content-Type` and `X-LocalDevVPN-Client` are the allowed headers.
* `Access-Control-Allow-Credentials` is never sent — do not use
  `credentials: 'include'`.
* **Mixed content:** `http://127.0.0.1` is a potentially trustworthy origin per
  the Secure Contexts spec, but WebKit's handling of such subresources from an
  `https://` page has varied by version. Test on your minimum iOS version. If it
  is blocked, either serve the signer from a loopback origin, or have the app
  serve the page. The deep-link flow does not remove this constraint: the token
  arrives over a URL, but the record is still fetched over HTTP.
* No TLS on the bridge: no CA will issue a certificate for `127.0.0.1`, and
  shipping a private key in the app to serve `https://` would be worse than plain
  HTTP over loopback.
* Chromium's Private Network Access preflight is answered when it asks
  (`Access-Control-Allow-Private-Network`). WebKit does not implement PNA.

### Networking

* One request per connection, no keep-alive; 64 KB body cap, 96 KB request cap,
  15 s idle timeout.
* The listener binds `127.0.0.1` only, and non-loopback peers are dropped at
  accept time as a second check.
* The port is not fixed. Probe `19842`–`19844`; a client that hard-codes one port
  will break when something else holds it.
* The bridge is unaffected by the tunnel: loopback traffic never enters the
  packet tunnel, so pairing works whether or not the VPN is connected.

## Trying it

`docs/pairing-bridge-demo.html` is a self-contained test client. Serve it from
the device (or open it from a local server) and use it to run either flow against
a build of the app.

Reference `curl` from a shell on the device:

```sh
curl -s -H 'X-LocalDevVPN-Client: curl' http://127.0.0.1:19842/v1/status
curl -s -H 'X-LocalDevVPN-Client: curl' -H 'Content-Type: application/json' \
     -d '{"client":"curl"}' http://127.0.0.1:19842/v1/sessions
# approve in the app, then
curl -s -H 'X-LocalDevVPN-Client: curl' http://127.0.0.1:19842/v1/sessions/$SESSION
curl -s -H 'X-LocalDevVPN-Client: curl' -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:19842/v1/pairing-record
```
