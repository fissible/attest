# NMS × attest — Integration Design Note (Laravel)

> Draft SME note (2026-06-09). How a Laravel **network-management system (NMS)** consumes
> `fissible/attest-laravel` to produce tamper-evident, optionally time-anchored evidence of device
> provisioning / uptime / status, and emits a customer-facing **signed verification report**.
> Lives here as an attest integration example until the NMS repo exists; move it there when it does.

## Decisions locked
- **Stack:** Laravel → `fissible/attest-laravel` (Eloquent storage, Artisan, queue-ready anchoring).
- **Chain granularity:** per **device**.
- **Report:** **both** — a portable `.attest` bundle *and* a rendered PDF certificate.

## Chain model
- One chain per device: chain id `device:{device_id}`, keyed on a **stable** identifier (serial / asset
  tag / UUID) — never a mutable name or IP.
- Multi-customer: set the envelope `tenant` field on `record()` (and index a `tenant` column) so reports
  can be filtered/scoped per customer.
- Optional later: a per-site rollup chain (`site:{site_id}`) for site-level commissioning/verification
  events. Start **device-only**; add the rollup only if reports need a site-level seal.

## Event taxonomy (envelope `type`s, versioned)
Record **state transitions + periodic attestations**, not every poll.
- `nms.device.provisioned.v1` — model, serial, firmware, config hash, location, installer.
- `nms.device.config.changed.v1` — before/after config hash, author, summary.
- `nms.device.firmware.updated.v1` — old/new version + hash.
- `nms.device.status.transition.v1` — up→down / down→up, with cause if known.
- `nms.device.uptime.attestation.v1` — periodic rollup: window, % uptime, checks performed, throughput
  sample, client count — i.e. the **real checklist result**, not "the device answered."
- `nms.device.decommissioned.v1` — retirement.

Payload guidance: record the *verification result* (what was checked and passed) + the measurement
method. Reference large artifacts (config dumps, pcaps) by `sha256` + URL, never inline — the signed
envelope is capped at 64KB.

## What gets recorded vs. polled
The NMS polls continuously (transient). It writes an **envelope** only on: a state transition, a
config/firmware change, provisioning/decommission, and a **periodic attestation** cadence (e.g. one
`uptime.attestation` per device per hour or per day). Keeps chains compact and meaningful.

## Storage
- `EloquentChainStore` via attest-laravel, on **MySQL/Postgres** (multi-writer safe — the NMS will have
  concurrent queue workers writing device events; SQLite is single-writer only).
- Config: `ATTEST_CONNECTION`, `ATTEST_SIGNING_KEY_SEED`, `ATTEST_SIGNING_KEY_ID` (e.g. `nms-prod-2026`).
- Write path: a queue job `RecordDeviceEvent` calls
  `Attest::chain("device:{id}")->record($type, $payload, tenant: $customerId)` — decoupled from the
  polling loop so signing/IO never blocks monitoring.

## Anchoring (the "timer nobody argues with")
- For SLA/dispute evidence, anchoring is **load-bearing** (provable time → can't backdate). Schedule
  `attest:anchor` per device chain (or batched) via the Laravel scheduler + the queueable
  `AnchorPendingBatch`, e.g. daily.
- **Caveat:** anchoring is `@experimental` in attest 1.x. This NMS/SLA use case is exactly the
  adversarial-audience scenario that would justify **graduating** anchoring to stable (attest roadmap
  "Path B" + the deferred live-network soak). Plan: enable anchoring in staging against real OTS
  calendars early to validate, and treat the anchoring API as not-yet-frozen until attest graduates it.
- Report policy: `--min-anchor=local_only` for internal use; `remote_header_confirmed` / `bitcoin_verified`
  for customer-facing disputes once anchoring is live.

## The signed verification report — two artifacts, one source
1. **Portable bundle (`.attest`)** — the machine-verifiable proof.
   `attest:bundle:export --chain=device:{id} --from=… --to=… --out=…`. The recipient runs
   `attest:bundle:verify` (or core CLI) with your **published** public key to confirm integrity +
   signatures + anchor coverage. Self-contained and tamper-evident.
2. **Rendered PDF certificate** — the human-facing view, generated from a **verified** segment.
   Flow: `Verifier`/Artisan verify → `VerificationResult` → render PDF (dompdf/snappy) showing: device
   identity, report window, per-event summary, overall outcome, **anchor outcome** (e.g. "Bitcoin-anchored,
   block time 2026-06-08T…"), the signing-key fingerprint, and a footer explaining how to independently
   verify the attached bundle.
   - **The PDF is a *view*; the bundle is the *proof*.** Embed/attach the `.attest` bundle (or a link + its
     `sha256`) in the PDF and tell the recipient how to verify it — so the pretty cert can never become a
     "trust me" substitute for the seal.

## Trust model
- Customers verify with **your published public key**, supplied out-of-band — not a key claimed inside the
  bundle (attest treats claimed keys as informational only). Publish the key + verify instructions.
- Key management: one signing key per environment (`ATTEST_SIGNING_KEY_ID`); rotation supported via
  per-envelope `key_id` + a multi-key trust set at verify time.

## Build order (dependency-first)
1. attest-laravel install + config + migrations; signing key.
2. `RecordDeviceEvent` queue job + event taxonomy; wire the NMS state machine → job.
3. Periodic `uptime.attestation` scheduler.
4. Bundle export (command/endpoint) for a device + window.
5. Verify + PDF rendering.
6. Anchoring scheduler — **after** the record/verify path is proven.

## Open questions to revisit
- Anchoring graduation timing (ties directly to attest's Path A→B decision).
- Per-site rollup chains — needed for site-level certs?
- Report window semantics — arbitrary date range vs. fixed billing periods.
- Retention — device chains grow unbounded; file-store rotation is an attest 1.1 item, and for Eloquent
  it's table growth → plan archival/partitioning.
