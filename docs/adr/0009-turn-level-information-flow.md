# ADR-0009: Session information-flow state ("Gate + Flow")

- Decision: **Proposed** · Owner/reviewer direction: approved in principle (architecture review round 2, 2026-11-25)
- Implementation: **Not approved**
- Date: 2026-11-25 · Revised after PR #8 review, batch 1 rounds 1 and 2 (B1–B4, R2–R4)
- Related: ADR-0003 (capabilities, provenance), ADR-0005 (identity, credentials), ADR-0006 (state store), ADR-0007 (ledger); threat model: [Gate + Flow](../product/threat-model-gate-flow.md)

## Context

Genesis Security v1 gates individual tool calls. Its residual risk R6 — a secret re-encoded (rot13, gzip, XOR) and sent to an **allowlisted** host — cannot be closed by inspecting content, because encodings are unbounded.

Research systems close this class with information-flow control. CaMeL attaches capabilities to every value and enforces policies at tool-call time; on AgentDojo it solved 77% of tasks with provable security versus 84% undefended ([Debenedetti et al., 2025](https://arxiv.org/abs/2503.18813)). That works because values flow through CaMeL's own interpreter.

**Genesis is a gate, not an interpreter.** When a model reads private data and writes new text, the output is a fresh string: a per-value label cannot survive the model. Flow state is therefore tracked per **session**, by the runtime.

> **Principles.** A security label is only as strong as the enforcement boundary that preserves it.
> Authentication proves who sent a message. Authorization proves what they may do. **Attestation proves what the trusted runtime actually enforced.** These three are never conflated.

## Decision

### 1. Two axes, never merged (closes B2)

Flow state has two independent axes:

| Axis | Question | Lattice | Combining data |
|---|---|---|---|
| **Confidentiality** | Who may receive this? | Set of data classes; allowed readers = intersection of their readers | **Join**: classes = union, readers = intersection. Combining can only make data *more restricted*, never less |
| **Integrity / provenance** | How far can this be trusted to direct actions? | Trust tier T0 (most trusted) … T3; provenance records | **Meet**: tier = least trusted input (highest T). Combining can only make data *less trusted*, never more |

```
FlowState = {
  confidentiality: { classes: set[str], readers: set[Reader] },
  integrity:       { tier: T0..T3,       provenance: list[ProvenanceRef] },
  session_id, task_id, version: int        # runtime-assigned; version increases on every change
}
```

(Conceptual shape, not an approved API.)

- Confidentiality decides **egress** (§6). Integrity decides **whether an action may be taken at all** (ADR-0003 L2: actions from T3 are blocked).
- **Invariant — readers are derived, never supplied.** At every egress decision the runtime computes

  ```
  effective_readers(session) = ⋂  ( policy.readers(c) ∪ valid_grants(session, c) )
                               c ∈ classes
  ```

  from the **receiver's current validated policy** and the session's valid declassification grants (§8). Grants are added **per class, before the intersection**: a destination must be allowed by every class in the session, either by policy or by a grant for that class. If `classes` is empty the flow rules do not apply and normal Gate rules decide (§6 step 2); the intersection over an empty set is never evaluated.

  > A declassification grant may widen readers only for the specific data class, session and scope it authorizes. It never widens readers for unrelated classes.

  Example: `private:accounts` → {owner, bank-api}, `private:payroll` → {owner, hr-api}. A grant of `hr-api` for `accounts` gives ({owner, bank-api, hr-api} ∩ {owner, hr-api}) = {owner, hr-api}; a grant of `bank-api` for `accounts` gives {owner} — `bank-api` still cannot receive payroll data. A `readers` value from an agent, a tool, or an envelope is never used as input; at most it is logged for diagnosis. So `classes` and `readers` cannot disagree: a session whose classes say "private" cannot hold a reader set that opens it.
- The two axes are tested independently, including the cross cases: confidential-but-trusted (bank records from the owner's database: `private:accounts`, T1) and public-but-untrusted (a web page with injected instructions: no class, T3). A value that mixes both carries both: `private:accounts` **and** T3.

### 2. Who records and attests flow state (closes B1)

**The Security Runtime, never the agent.**

- The runtime classifies data and updates flow state itself, from what it observes at the gateway: which declared tool returned data, under which `produces` classes (§3), from which source.
- **Agents do not sign envelopes and do not hold envelope-signing credentials in mode 02.** An agent *requests* "send this to B"; the runtime looks up the sender session's flow state in the state store, builds the envelope from that state, and signs it with the runtime credential for the sender identity (ADR-0005). The agent cannot choose the flow state that goes into the envelope.
- **The receiving runtime does not trust the flow state written in an envelope as evidence that data is clean.** It raises the receiver's state to at least the sender's state recorded in the shared state store, referenced by `(session_id, version)` and a digest in the envelope. The envelope can only **raise** the receiver's state, never lower it: `receiver := join(receiver, store_state(sender), envelope_claim)`.
- **Signing authority, stated precisely.** In mode 02 the *technical signer* of every envelope is the Security Runtime. It signs **on behalf of** the sender's agent identity, using the identity-bound provider it holds (ADR-0005 §3), and it is the party responsible for the attestation. Consequently:
  - a valid signature proves that **the runtime** attested this flow state for this sender identity — it does **not** prove that the agent produced, saw or agreed to that state;
  - the sender identity in an envelope is accepted only after the receiving runtime checks it against the authoritative store record for `session_id` (the session must belong to that identity);
  - no agent has private signing authority of its own in mode 02.
- **Authoritative store.** "Shared state store" means one **authoritative** store that only the runtimes of the same deployment can write and that agents cannot reach (ADR-0006). The `(session_id, version, digest)` check is made against that record, never against a copy supplied with the message. Runtimes without access to the same authoritative store cannot verify each other's attestations (cross-host case below).
- **No trusted state evidence → owner-only.** If the store record is missing, unreadable, older than the envelope's `version`, or the digest does not match: the receiver is raised to `private:unclassified` (owner-only) and integrity T3, and a `GSX-07` event is logged. Lowering is refused.

**Process boundary — what this does and does not cover (stated honestly):**

| Deployment | Protects against | Does **not** protect against |
|---|---|---|
| **Out-of-process runtime** (sidecar / gateway process, separate OS user) | A manipulated model **and** compromised agent code: the agent process never holds a signing credential and cannot write the state store | Compromise of the runtime process or host |
| **In-process library** (today's v1 shape) | A manipulated model: models emit text, they cannot read keys or call the store directly | **Compromised agent code**: Python offers no memory isolation inside one process; code in that process can reach the runtime's keys and store connection |

Mode 02's cross-agent guarantee is therefore claimed **only for the out-of-process runtime**. In-process mode 02 is supported for single-agent use and is labelled accordingly by `doctor`.

Cross-host relays (runtimes on different machines) require runtime-to-runtime attestation with runtime identities and a shared or federated state store; this is **out of Core v2.0 scope** (Enterprise, Phase 3). Without it, a message from another host's runtime is treated as unverifiable (owner-only, T3).

### 3. Data classes and sources are declared in policy (schema 2)

```toml
[data_classes."private:accounts"]
readers = ["spiffe://genesis.local/owner", "sink:bank-api"]

[tools.read_statement]
capabilities = ["read"]
produces = ["private:accounts"]          # data returned by this tool raises confidentiality
integrity = "T1"                          # source trust of what it returns (default T3)
```

- Only the validated policy declares classes, which tools produce them, and their source trust. Agents and models cannot.
- A tool that returns data without `produces` produces `private:unclassified` (readers: owner only). **Default is private.** Without `integrity`, returned data is T3. **Default is untrusted.**

### 4. Ordering and atomicity (closes B3)

The race to close: worker A reads private data while worker B, in the same session, sends something out; B's egress must not be authorized against a state that does not yet include A's read.

**Read path (raise before release):**

1. Before executing a declared read tool, the runtime **pre-raises** the session to the tool's `produces` classes (and lowers integrity to its declared tier) in one transaction, and commits. The state is now at least as restrictive as it will be after the read.
2. The tool executes.
3. The runtime records the read in the ledger, then **releases the result** to the agent.

If step 1 fails, the tool does not run. If 2 or 3 fails, the pre-raise stays (state never falls by itself) and nothing is released. A restart at any point leaves state raised or unchanged, never lowered.

This closes the race between **data disclosure and flow-state elevation**. It does not, by itself, close the gap between an egress **authorization** and the **external side effect**: a database transaction cannot make a network operation atomic with it. That second gap is closed by a version-bound, single-use permit.

**Egress path (authorize → permit → revalidate → act):**

1. **Freeze the payload.** The gateway serialises the request itself — request line, every header in final order and form, and body — into **one immutable byte buffer**, and computes `payload_digest = SHA-256(buffer)`. The digest covers the **HTTP application bytes** handed to the TLS layer as application data, not TLS records or ciphertext. There is no separate "canonical form": the buffer that was hashed is the buffer that is sent. To make that possible in mode 02:
   - the gateway uses its own HTTP/1.1 serialiser (no HTTP/2 in Core v2.0 mode 02); gateway-managed headers (`Host`, `Content-Length`, and any credentials the gateway injects) are computed **before** the digest; `Transfer-Encoding`, `Connection`, `TE`, `Upgrade` and `Expect` are not sent;
   - no client-side transformation after the digest: no automatic compression, header insertion, case changes, redirects or retries (a retry is a new request needing a new permit);
   - a streamed or lazily built body is materialised first, or the call is BLOCKED;
   - at step 4, **before the first byte is sent**, the gateway recomputes the digest of the buffer and compares it with the permit; a mismatch → BLOCK. It then writes **that same buffer object** directly to the TLS connection's application-data stream. No re-serialisation, copy through another serialiser, or transformation is permitted after this check.
2. **Authorize** (`BEGIN IMMEDIATE`): read the committed flow state at version `v`, evaluate readers and sink policy (§5, §6), and on ALLOW write a **permit** and the ledger decision, then commit:

   ```
   permit = { permit_id (128-bit random), session_id, sink, payload_digest,
              issued_version: v, revalidated_version: null, consumed_version: null,
              policy_fp, issued_at, expires_at (default 30 s), status: issued }
   ```

3. **Revalidate and consume** (`BEGIN IMMEDIATE`, immediately before sending): the permit must exist, be `issued`, unexpired, and match `session_id`, sink and `payload_digest`; the policy fingerprint must be unchanged. Record the current version as `revalidated_version`. If it is still `v`, set `status: consumed`, `consumed_version: v`, and commit. If the version has changed, **re-run step 2's evaluation against the current state**; consume only if it still allows this sink (`consumed_version` = the new version, and the ledger records the re-evaluation), otherwise mark the permit `revoked` and BLOCK. Auditors therefore see the version the send was actually authorized under, not only the version at issue.
4. **Send** exactly the frozen bytes, then record the outcome (`sent`, `failed`, `unknown`) with `issued_version`, `revalidated_version` and `consumed_version` in the ledger.

Why the window after step 3 is safe: between consuming the permit and the bytes leaving, state may still rise, but the payload was frozen in step 1, and data is released to agents only after its raise is committed (read path). Data that raised the state after step 1 cannot be in those bytes. The permit ensures that the bytes sent are the bytes that were authorized, and that the authorization was checked against the latest committed state no earlier than the permit's consumption.

Permit rules: single use (a second consume fails); bound to one session, one sink and one payload digest; expiry is short and not renewable; permits are never issued by, passed to, or visible to agents. **Restart:** on start-up, every `issued` permit is marked `expired` and its call is **not** executed (at-most-once); a `consumed` permit with no recorded outcome is recorded as `outcome: unknown` and is **never** retried automatically. Any lock timeout, write failure or store error at any step → **BLOCK**.

Tests required: parallel read + egress in one session (threads and processes); state raised between authorization and revalidation (must re-evaluate and BLOCK when the sink is no longer a reader); permit reuse; permit for another session, sink or payload; payload changed after authorization; expired permit; restart between pre-raise and release, between authorization and revalidation, and between consume and send; lock contention timeout; write failure — none may produce unauthorized egress.

### 5. Sink resolution (closes B4)

A **reader** is a principal (identity URI, ADR-0005) or a named **sink**. Egress is authorized against the sink the bytes will *actually* reach, resolved by the gateway, not against what the agent names.

```toml
[sinks."sink:bank-api"]
capability   = "network"
scheme       = "https"
host         = "api.bank.example"
port         = 443
path_prefix  = "/v1/transfers/"
methods      = ["POST"]
verification = "tls-spki-pin"                    # tls-hostname | tls-spki-pin | mtls-spiffe
spki_sha256  = ["<base64 SHA-256 of SPKI>"]       # PLACEHOLDER — required for tls-spki-pin; not a usable value
# principal = "spiffe://bank.example/api"        # allowed ONLY with verification = "mtls-spiffe"
recipient_mode = "fields"                         # fixed | fields
arguments_closed = true                           # any argument not declared below → BLOCK

[[sinks."sink:bank-api".recipient_fields]]
location = "body"                                 # header | query | path | body | form | metadata
pointer  = "/beneficiary_account"                 # header name, query key, path template var, JSON Pointer
allow    = ["acct:owner-*"]

[sinks."sink:bank-api".onward]
onward_sharing = false
onward_sharing_basis = "assumption"              # assumption | contract:<ref> | technical:<ref>
```

Resolution rules:

1. **The gateway performs the egress.** Network- and message-capable tools in mode 02 must use the gateway's client; a tool that opens its own connection is outside the boundary (§9).
2. **Canonicalize** (ADR-0003 §5): scheme and host lower-cased, IDNA host, default port made explicit, path percent-decoded once then normalised; dot-segments, encoded slashes (`%2F`), backslashes, userinfo, and mixed-script hosts → **BLOCK** (not HOLD: ambiguity is not resolved by a human click).
3. **Match** scheme, host, port, path prefix and method exactly.
4. **Redirects off by default.** If a sink enables them, each hop is re-resolved and must match the *same* sink; a hop to anything else aborts before any body is sent on that hop.
5. **DNS:** resolve once per new connection, refuse private/loopback/link-local/unspecified addresses unless the sink declares them, and connect to the address that was checked (no re-resolution mid-request) — closing DNS rebinding.
6. **Connection reuse:** the gateway's pool is keyed by `(sink name, verified IP, port, verification mode, pinned keys)`, and for `mtls-spiffe` also by `(client SVID identity, client credential epoch, trust-bundle fingerprint)`. When any of these changes — pins edited, credential rotated or revoked, trust bundle updated — the affected connections are closed **immediately**, not at pool expiry. A connection is reused only for the **same sink** and the same verified address, never for another sink, even one with the same host. HTTP/2 connection coalescing and TLS session resumption across sinks are disabled. Pooled connections are closed on policy reload, on sink definition change, and after a bounded lifetime (default 5 min), after which DNS and TLS checks run again. Tools cannot supply their own client or pool.
7. **Proxies:** environment proxy settings are ignored; a proxy is used only if declared on the sink. The runtime resolves and checks the end server's address itself (rule 5) and sends `CONNECT <verified IP>:<port>` — never a hostname — then runs TLS to the end server with the sink's hostname for SNI and verification (rule 8). A proxy that will only accept hostnames (and so resolves DNS itself) is **unsupported in mode 02**: it would remove the DNS-rebinding guarantee.
8. **Verification levels — what each one proves.** The channel proves identity; the agent never does. The three modes give different guarantees and are reported by their own names, not as a generic "principal verified":

   | `verification` | Proves | Does **not** prove |
   |---|---|---|
   | `tls-hostname` (minimum) | The server holds a certificate for the sink's **hostname**, valid under the system trust store | Which organisation or service runs it; any SPIFFE identity |
   | `tls-spki-pin` | The server holds one of the **pinned public keys** (and the hostname check passes) | Any SPIFFE identity |
   | `mtls-spiffe` | The server presents an X.509 SVID whose URI SAN equals the declared `principal`, chaining to the configured trust bundle of that **trust domain**; the runtime authenticates with its own SVID | — (strongest; requires a configured trust bundle) |

   A sink may declare a `spiffe://` `principal` **only** with `mtls-spiffe`; any other combination is rejected when the policy loads. Without it, the reader is the sink name (`sink:bank-api`) bound to its host and keys, not a principal. `mtls-spiffe` ships only if its conformance tests pass; until then it is rejected as unsupported, never silently downgraded.
9. **Recipient selection.** Every sink declares `recipient_mode`:
   - `fixed` — the endpoint alone determines the recipient. The tool's arguments must not be able to select another one.
   - `fields` — each place that can select a recipient is listed with its `location` (`header`, `query`, `path`, `body` via JSON Pointer, `form`, or `metadata` such as `to`/`cc`/`bcc`, `channel_id`, `thread_id`) and an `allow` list. **Every** occurrence is checked; for arrays, **every** element must match; a missing required field → BLOCK.

   **Closed arguments.** In mode 02, every network/message sink must set `arguments_closed = true`, which covers **every** location: tool arguments, path parameters, query keys, headers, body members (at any depth), form fields and message metadata (including `channel_id` and `thread_id`). Anything not declared in the sink's argument schema or as a recipient field → **BLOCK**. Protocol-managed headers (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `TE`, `Upgrade`, `Expect`, and gateway-injected credentials) are produced by the gateway only; if an agent or tool supplies any of them → **BLOCK**.

   **The gateway is the only encoder.** Inputs reach the gateway in one of two forms, with different rules:

   | Input form | Rules | Example |
   |---|---|---|
   | **Structured fields** — path parameters, a query map, a header list, a body object, form fields, metadata, passed as typed values | Validated against the sink's **argument schema** per field (type, length, allowed characters); CR, LF, NUL and other control characters are rejected in every field; recipient fields are then matched against `allow`. The strict parsing steps below do **not** apply; the gateway encodes the values itself, once, when it builds the buffer (§4 step 1) | `to = "user@example.com"` in metadata → allowed if the schema and `allow` permit it |
   | **Ready-made strings** — an absolute URL, a query string or a form body supplied as text | Absolute URL: authority validation → strict parsing steps 1–5. Query string: strict parsing only. Form body: strict parsing only. Authority validation applies **only** to absolute URLs | `https://api.bank.example/v1/transfers/?to=user@example.com` → **BLOCK** (`@` in a recipient value, step 3) |

   | Case | Result |
   |---|---|
   | Structured body field `user@example.com` | Allowed per schema and `allow` |
   | Same value as a recipient inside a ready-made URL | BLOCK (strict parsing) |
   | Structured field containing CR or LF | BLOCK |
   | Structured field that does not match its schema | BLOCK |

   After the gateway has encoded a value, no component inside the boundary decodes or interprets it again.

   **Absolute-URL authority rules** (absolute URLs only — never to a standalone query string or form body; applied before steps 1–5, on the raw string, consistent with §5 rules 2–8):

   - The URL must be **absolute** and start with exactly `https://` (lowercase); any other scheme, a scheme-relative (`//host`) or relative URL → BLOCK.
   - Authority = the text between `https://` and the first `/`, `?` or `#`. **Reject** if it contains `@` (userinfo), `\`, whitespace, control or non-ASCII characters, or `%`.
   - **Classify the host first**, then compare by type:

     | Host form | Classified as | Rule |
     |---|---|---|
     | Enclosed in `[ ]` | IPv6 literal | Rejected unless the sink declares an IPv6 literal. The input must be in the **RFC 5952 canonical text form** (lowercase hex, no leading zeros, `::` for the longest run of two or more zero groups, leftmost on a tie, no embedded IPv4 notation, no zone ID such as `%25eth0`); any other spelling → BLOCK, even if it denotes the same address. It must then equal the declared literal, which the policy loader also requires to be in RFC 5952 form |
     | Last label begins with a digit, or any label begins with `0x` | IPv4 literal (or an attempt at one) | Rejected unless the sink declares an IPv4 literal. The **only** accepted form is four dot-separated decimal octets, each `0`–`255`, with no leading zeros (`10.0.0.1`, never `010.0.0.1`, `0x0a.0.0.1`, `167772161` or `10.1`). Anything else in this class → BLOCK. It must then equal the declared literal exactly |
     | Otherwise | DNS hostname | Labels of `[a-z0-9-]` after ASCII lower-casing, no trailing dot, no empty label; must **equal the sink's declared hostname** exactly |

     A sink declares either a hostname or one IP literal, never both; an IP literal never matches a hostname sink, and a hostname never matches an IP sink. Because the accepted spellings are unique, string equality is a sufficient comparison.
   - Port: absent → the sink's default; present → must be decimal digits without leading zeros, equal to the sink's `port`; an empty port (`host:`) → BLOCK.
   - A **fragment** (`#…`) anywhere → BLOCK.
   - Any character outside the RFC 3986 URI character set, or more than one `?` → BLOCK.
   - The verified sink then supplies the connection target: DNS binding (rule 5), proxy `CONNECT` (rule 7) and TLS verification (rule 8) use the sink's declared host, never a host taken from the string.

   Strict parsing of ready-made path, query and form strings, in this fixed order:

   1. **Split by structure first, on raw text:** path into segments on `/`; query into pairs on `&`, then each pair into key and value on the first `=`; form bodies the same way. Nothing is decoded before splitting.
   2. **Decode each component exactly once:** percent-decoding (RFC 3986) for path and query; for forms, `+` → space then percent-decoding (application/x-www-form-urlencoded).
   3. **Reject** if a decoded **key** or **recipient value** contains `%`, `+`, `\`, a control or non-ASCII character, or any reserved character (`/ ? # [ ] @ ! $ & ' ( ) * , ; =`); if a decoded **path segment** contains `/`, `\`, `?` or `#` (from `%2F`, `%5C`, `%3F`, `%23`); if a path segment is `.` or `..` **however it was written** — literal (`/api/../admin`), fully encoded (`%2E%2E`), or mixed (`.%2E`, `%2e.`) — checked on the decoded segment, so every representation is rejected the same way; if a path contains an empty segment (`//`) other than the single leading `/`; or if any component still contains a `%` followed by two hex digits after one decode (e.g. `%25xx`).
   4. **Detect duplicates on the decoded keys** (step 2 output), so `beneficiary` and `benefici%61ry` are the same key → **BLOCK**.
   5. The gateway then re-encodes the validated structure itself to build the buffer.

   How the **remote** server decodes is outside the boundary; that is why step 3 rejects any key or recipient value whose meaning could change under a second decode or a different delimiter rule.

   **Matching grammar for `allow`.** Each entry is either an exact literal or a literal followed by a single trailing `*` (prefix match). A `*` anywhere else, character classes and regular expressions are rejected when the policy loads. Values are compared as exact strings after the single decode above (JSON string unescaping for body values); no case-folding, trimming or Unicode normalisation.

   **Duplicates and multiple locations.** Duplicate header names (case-insensitive), duplicate query keys and form fields (compared after decoding, step 4), and duplicate JSON object keys → **BLOCK**. JSON duplicate detection is **recursive at every object at every depth** (e.g. two `to` keys inside `message`), compares keys **after** JSON unescaping (`"\u0074o"` equals `"to"`), and happens in the gateway's own parser before anything is forwarded; a parser that silently keeps the last value is not used. A recipient value appearing in a location not declared for it → **BLOCK**; if it is declared in several locations, every occurrence must match. The meaning of the allowlist therefore does not depend on any client's or server's parser. Tools that can choose a recipient by indirect means the gateway cannot see (server-side address books, templates, IDs resolved by the remote service) must expose that selector as a recipient field; if they cannot, they are **unsupported in mode 02** and the policy is rejected.
10. **`onward_sharing` is a declaration, not a proof.** Its `onward_sharing_basis` records whether it is an assumption, backed by a contract, or by a technical control. Reports and `doctor` show the basis; the guarantee in §11 inherits it.

### 6. Egress enforcement

For every call with a `network` or `message` capability:

1. Resolve the destination to a sink (§5) or principal. Unresolvable → **BLOCK**.
2. If the session's confidentiality axis is empty → normal Gate rules.
3. Otherwise the resolved reader must be in `effective_readers(session)` (§1 formula) → else **BLOCK** (`GSX-06`; reason names class and sink). Not HOLD: readers are widened by policy or declassification, never by approving one leak.
4. Content is **not** inspected for this decision: rot13, base64, unicode transformations or paraphrase change nothing.

### 7. Combining across classes

Allowed readers are the **intersection** of the readers of every class in the session. Empty intersection → no egress until declassification (§8).

### 8. Declassification (closes R2)

| Path | Allowed? | Conditions |
|---|---|---|
| **Model-requested** | Request only | A model or agent may *ask*; the request is logged; it never changes state by itself |
| **Runtime automatic** | **Never** | No time-based, size-based or heuristic declassification |
| **Human-approved** (Human Gate) | Yes | Owner identity authenticated; dedicated declassification prompt showing class, session, destination scope and reason |
| **Owner-authorized policy rule** | Yes, narrowly | Rule created or approved by the owner, signed/authenticated with the policy (ADR-0004); must name class, allowed reader(s) or sink(s), max use count and expiry; may not name "any" |

Every declassification records: owner identity, session ID, task ID, data class, granted scope (readers/sinks), reason, policy ID + version, timestamp, and a **single-use approval token** bound to `(session_id, class, scope, nonce, expiry)`. A token is rejected for any other session, class or scope, after use, or after expiry. A grant is stored as `(session_id, class, readers/sinks)` and adds readers **for that class in that session only** (§1 formula); it never edits the class's readers in policy and never applies to any other class.

### 9. Enforcement boundary

Guarantees hold **only for egress performed by the Execution Gateway**. Deployments declare their boundary. In mode 02 the runtime refuses to start if an in-process network/message tool is registered outside the gateway; for out-of-process tools the deployment guide requires OS-level egress rules that permit only the gateway. `genesis-security doctor` reports what it verified and what it could not. Any failure to read or write flow state → **BLOCK**.

### 10. Sessions, tasks and envelopes across policy versions (closes R3, R4)

**Session and task isolation (R4):**

- Session IDs and task IDs are generated by the runtime (128-bit random); callers cannot choose or reuse them.
- Every task records its parent session/task; a task inherits the parent's flow state.
- A **clean task** requires owner authorization (same record and single-use token rules as §8). It starts with an empty confidentiality axis **without changing the parent's state**, and it may not receive data from the parent except through declassification.
- A new session is not clean if anything enters it from another session: inputs are admitted only through the runtime's typed constructors (ADR-0003 §4), which attach the origin session's flow state and raise the new session accordingly. Data carried in without provenance is owner-only and T3.
- Cross-session transfers are logged as such.

**Policy compatibility (R3):** envelopes carry `policy_id`, `policy_version`, `schema_version` and `policy_fp`, all covered by the signature.

- `policy_id`: 128-bit random value generated at `init`, one per deployment; it identifies *whose* policy this is.
- `policy_version`: integer, increased by the owner on every accepted policy change.
- `policy_fp`: `SHA-256` over the **validated effective policy** — every default materialised, so two TOML files with the same effect have the same fingerprint — serialised with the JSON Canonicalization Scheme of **RFC 8785**. To keep canonicalisation unambiguous, the effective policy is restricted to an I-JSON subset that the validator enforces before hashing: object keys are ASCII (so RFC 8785's UTF-16 key ordering equals byte ordering); numbers are integers in the safe range −(2⁵³ − 1) ≤ n ≤ 2⁵³ − 1, inclusive (no floats, so no number-formatting or NaN/Infinity cases; ±2⁵³ itself is rejected); no duplicate keys (TOML forbids them, and the converter refuses them); strings are valid UTF-8 without lone surrogates, escaped per RFC 8785 §3.2.2.2. Conformance means reproducing RFC 8785's published examples within this subset plus Genesis test vectors; a generic `json.dumps(sort_keys=True)` is **not** assumed to be equivalent. Equal fingerprints mean the same effective rules; a fingerprint is not a secret and not an authenticity proof (authenticity of the policy is ADR-0004's job).

Comparison never imports the sender's rules: the receiver always computes readers from **its own** policy (§1 invariant). The receiver's state store keeps, durably, the **current** and **immediately previous** accepted `(policy_version, policy_fp)` pairs; they change only when the owner installs a new policy, never because of an envelope.

**Monotonic installation.** Under one `policy_id`, every owner-installed policy must have a `policy_version` **strictly greater** than the current one. Installing a lower version, or reusing a version number already installed (even with the same content), is rejected; to restore old rules the owner installs them again under a new, higher version. Starting a new policy lineage requires a new `policy_id`, created only through an owner-authorized, audited operation (`genesis-security policy new-lineage`); every runtime of the deployment must install it, and until then envelopes under the other `policy_id` are treated as from another deployment (owner-only, T3). This keeps the downgrade rules below meaningful at the source, not only at the receiver. Version and fingerprint are always checked **together**:

| Envelope `(policy_version, policy_fp)` vs receiver | Meaning | Action |
|---|---|---|
| = current version **and** = current fp | Same rules | Accept class names as-is |
| = previous version **and** = previous fp | Policy changed while the message was in flight | Compatibility check: map classes by name; unknown → `private:unclassified`; ledger event `flow.policy_drift` |
| Version older than previous | Stale or replayed | Owner-only, T3, ledger event `flow.policy_stale` |
| Same version as current or previous, **different** fp | Inconsistent (forged or corrupted policy state) | Owner-only, T3, ledger event `flow.policy_mismatch` (alert) |
| Version newer than current | Receiver has not installed it | Owner-only, T3 until the owner installs that policy; the envelope never installs or selects a policy |
| Any other combination / unknown fp | Unknown policy state | Owner-only, T3 |

No envelope can make the receiver evaluate under an older policy: the receiver evaluates under its **current** policy in every row; the table only limits how much of the sender's labelling it trusts.

The receiver then applies:

| Case | Action |
|---|---|
| Unknown data class | Treat as `private:unclassified` (owner-only) |
| Readers named in the envelope | Ignored as input; readers are recomputed from the receiver's policy (§1 invariant), so a reader unknown to the receiver can never be reached |
| `schema_version` newer than supported | **BLOCK** the message |
| Different `policy_id` (other deployment) | Unverifiable → owner-only, T3 |
| Same `policy_id`, different `policy_fp` | Per the fingerprint table above; never lower the state received |
| Provenance unverifiable | Owner-only, T3, `GSX-07` event |

A signature valid under one policy is not evidence of safety under another.

## 11. What this does and does not guarantee

| Guaranteed — inside the enforcement boundary, with an out-of-process runtime | Not guaranteed |
|---|---|
| Data of a declared class cannot reach a reader outside its allowed readers via the gateway, regardless of encoding | Egress outside the gateway (direct sockets, other processes) |
| Sink identity at the declared verification level only — hostname, pinned key, or SPIFFE ID (§5.8) | A stronger identity than the declared level (e.g. who operates a host verified only by `tls-hostname`) |
| Flow state is recorded and attested by the runtime; agents cannot lower their own or others' state | Compromised agent code in **in-process** deployments (§2) |
| Concurrent reads and egress cannot race past the policy; an authorization is used once, for the exact authorized bytes, and is re-evaluated if state changed before sending (§4) | Compromise of the runtime or host |
| Only the owner declassifies; approvals are single-use and scoped (§8) | That a sink honours `onward_sharing = false` beyond its declared basis (§5.10) |
| Confidentiality can only rise and integrity only fall when data is combined (§1) | Action-selection leakage (choosing *which* allowed action reveals information) — addressed only by Plan-Constrained Execution |
| | Covert/timing channels inside an allowed sink; cross-host relays (Core v2.0) |
| | Atomicity of the network side effect itself: outcome may be `unknown` after a crash; such calls are never retried automatically (§4) |

## Dependencies

Identity & credentials (ADR-0005, authenticated sender) → trusted runtime & state store (ADR-0006: integrity, atomicity, provenance) → information-flow engine (this ADR: confidentiality, readers, declassification) → sink resolution & Execution Gateway (§5, ADR-0003: authorization, egress) → auditable decision (ADR-0007).

## Consequences

- Closes residual R6 inside the boundary, by structure instead of detection.
- Introduces an out-of-process runtime as the recommended deployment for mode 02.
- Utility cost is measured, not assumed — see the [evaluation plan](../product/evaluation-plan-agentdojo.md) (*Maximum Acceptable Benign Task Regression*).
- Confidence that this is the most valuable next control: **65 %, unearned**. Revisit after the evaluation.

> **Principle:** Never confuse detection with enforcement.
