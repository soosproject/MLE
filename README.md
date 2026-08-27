# Mandate Lifecycle Events (MLE)

**A proposed Shared Signals Framework (SSF) profile — companion to, not an extension of, WISE**

**Author:** T. Sato, MyAuberge K.K.
**Date:** 27 August 2026
**Status:** Initial review draft — not yet submitted, prepared for discussion

**Base URI:** `https://schemas.openid.net/secevent/mandate/event-type/` *(placeholder — open to
discussion, including whether this should sit under a shared namespace with WISE)*

## Abstract

This profile defines Security Event Token (SET) event types for signaling changes to an AI
agent's *mandate* — the delegated authority under which it acts — as distinct from its
credential or its current task. Existing Shared Signals profiles model human sessions (CAEP),
human accounts (RISC), and workload authentication (WISE). None of them model whether an
already-authenticated, still-credentialed workload is still *authorized* to be doing what it's
doing. This profile fills that gap.

## 1. Introduction

Picture a company that deploys an AI agent with a mandate — the authority to negotiate vendor
contracts up to $50,000, granted by a procurement lead as part of a Q3 procurement push. That
grant of authority is the mandate: not the agent's identity, not its task, but the specific,
bounded permission it was given, by a specific person, to act. Partway through the quarter, the
budget gets cut. The procurement lead withdraws the mandate — the agent no longer has authority
to keep negotiating.

On the other side of this negotiation is a **Receiver**: the vendor's own contract system,
receiving proposals and counter-offers from the agent and ultimately deciding whether to
countersign a deal. It has no independent way of knowing that the procurement lead just pulled
the plug. If the agent sends one more counter-offer after its mandate was withdrawn, the
Receiver has no signal telling it that offer no longer carries real authority behind it. It's not
the Receiver's negotiating counterpart it needs to worry about being confused; it's whether it's
about to countersign a contract with no one actually standing behind it. This is exactly what a
mandate-revocation event is for: it's the signal that reaches the Receiver, not just the agent's
own operator, telling it the authority behind what it's looking at just changed.

The agent's credential — the thing it authenticates with — hasn't changed at all. Nothing about
its key material, its session, or its workload identity is any different than it was five minutes
earlier. If you're watching WISE's event stream, or CAEP's, or RISC's, you see nothing, because
from the standpoint of every existing Shared Signals profile, nothing happened. The agent is
still exactly who it was. It's simply no longer *allowed* to keep doing what it's doing — and
there is currently no standard way to say that.

This is not a hypothetical. Anyone who has actually operated agentic systems in production runs
into this gap almost immediately, and it tends not to be obvious until it's already caused a
problem: existing security-event vocabulary was built for a world where authentication and
authorization change together — revoke the credential, and the authority goes with it. Agentic
systems break that assumption. An agent's credential is typically provisioned for a session or a
task lifetime; its *mandate* — what it's actually been authorized to do, on whose behalf, and
within what limits — can change independently and faster. Budgets get cut. Scope gets narrowed. A
human decides a task should stop. None of that is a credential event. All of it needs to reach
every system relying on that agent's authority, in real time, the same way a compromised
credential does today.

Three things make this worse than it sounds at first:

- **Delegation.** A real agentic deployment isn't one agent — it's a chain. A negotiating agent
  may spawn a research sub-agent, which may spawn a pricing-lookup sub-agent. If the root mandate
  is withdrawn, every descendant mandate in that chain needs to know, not just the agent at the
  top. A credential-level signal has no concept of this; a mandate needs to.
- **Irreversibility.** Session revocation for a human is usually about locking someone out.
  Mandate revocation for an agent is often about stopping an action that cannot be undone — a
  contract about to be signed, a payment about to be sent, a resource about to be deleted. The
  urgency is qualitatively different, and the signal needs to reach the agent (or whatever's
  about to act on its behalf) before the irreversible step, not after.
- **Independence from task state.** An agent's mission — what it's trying to accomplish — can be
  entirely unaffected by a mandate change and still need to stop. The agent isn't confused about
  its goal; it's no longer permitted to pursue it. This is a genuinely different kind of event
  than "the task failed" or "the task succeeded," and existing lifecycle vocabulary doesn't have a
  slot for it.

WISE was the first profile to say clearly that workload identity needs its own signaling layer,
separate from human sessions and accounts. This profile makes the same argument one layer up: an
agent's *authority* needs its own signaling layer, separate from its identity. The two are meant
to be used together — a WISE Receiver already knows how to react to a compromised credential;
this profile gives it the equivalent vocabulary for a withdrawn mandate.

### 1.1. Scope

Events signaling the full lifecycle of a mandate — the delegated authority a workload holds to
act on behalf of a principal — from request through execution to revocation. This profile tracks
authority, not workload credentials, and is intended as a general SET/SSF profile rather than a
WISE-specific extension.

### 1.2. Alignment with WISE

This profile is designed to be deployed alongside WISE, not to modify it. Specifically, it
inherits the following from WISE and the core SSF Framework rather than redefining them:

- The `uri`/`wimse://` workload subject identifier format (§3), used here for the `workload`
  member of this profile's Complex Subject.
- The Common Optional Claims pattern (§2) — `reason_admin`, `reason_user`, and
  `initiating_entity` — reused with the same localizable-object structure WISE inherits from
  CAEP.
- The base SET/JWT envelope, `iss`/`aud`/`iat`/`jti` claims, and replay/freshness handling (§5.1),
  unchanged from WISE §4.1–4.2.

What this profile adds, that WISE does not cover: mandate — as opposed to credential — lifecycle
events, and a `principal` Complex Subject member representing the human or organization the
mandate traces back to, which WISE's workload-only subject has no equivalent for. A deployment
running both profiles is expected to correlate a `mandate-executed` event here with the WISE
credential events describing the workload presenting that credential, via `mandate_id` and/or the
issued credential's own identifier — this profile does not define that correlation mechanism
further; it is a deployment-level integration question.

### 1.3. Terminology

There are several existing terms — Goal, Mission, Intent — that sound adjacent to "Mandate."
This section grounds the term precisely rather than leaving it to inference.

**Mission / Goal / Intent** — what a workload is trying to accomplish. A Mission describes *what
the workload is doing* — it says nothing about whether the workload is *allowed* to do it. Two
workloads can share an identical goal while holding completely different authority to pursue it.

**Mandate** — the authorization to act, independent of the task itself. A mandate binds a
workload's authorization to a specific, governed scope, under a named human or organizational
principal. A mandate answers *is this workload permitted to act, on whose authority, and within
what bounds* — not what the workload intends to do. This is the load-bearing distinction for the
whole profile: **Mission is the "what," Mandate is the "may."**

**Credential** — the artifact presented on the wire that carries evidence of a mandate for a
specific call or transaction. A mandate is a standing grant; a credential is its momentary
presentation. `mandate-executed` (below) is where this profile makes that distinction concrete —
one mandate may produce many credentials over its lifetime (a new one per transaction), of
several possible types (opaque token, JWT, Transaction Token), and revoking the mandate does not
retroactively invalidate a credential already issued from it — see the Notes under
`mandate-revoked`.

**Working definition adopted by this profile:** *A mandate is a scoped, time-bounded delegation
of authority from a principal to a workload, distinct from the workload's mission (what it is
trying to accomplish) and from any credential issued under it (the per-transaction artifact
proving that authority at the point of use).*

### 1.4. Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as
shown here.

---

## 2. Common Optional Claims

Unless stated otherwise, any event defined in this profile MAY include the common optional claims
defined in Section 2 of [CAEP], reused here in the same form WISE reuses them:

- **`reason_admin`** — OPTIONAL. A localizable administrative message intended for logging and
  auditing. Its value is a JSON object containing one or more key/value pairs, where each key is
  a BCP 47 [RFC5646] language tag and each value is the locale-specific message.
- **`reason_user`** — OPTIONAL. A localizable, user-facing message, following the same JSON
  object structure as `reason_admin`.
- **`initiating_entity`** — OPTIONAL. A JSON string describing what triggered the event: one of
  `admin`, `user`, `policy`, or `system`.

When an event in this profile includes `reason_admin` or `reason_user`, the claim MUST use the
localizable JSON object structure defined above rather than a plain string. The following is a
non-normative example:

```json
"reason_admin": {
  "en": "Q3 procurement budget reduced; vendor negotiation halted",
  "de": "Q3-Beschaffungsbudget reduziert; Lieferantenverhandlung ausgesetzt"
}
```

---

## 3. Subject: `sub_id` and Complex Subjects

Per the core SSF Framework spec (§3.1.2), new event types MUST use the top-level `sub_id` claim —
not the legacy nested `subject` field inside `events` that older CAEP/RISC events use. All events
below follow this.

Several events here involve more than one party — the principal delegating authority and the
workload receiving it. SSF's **Complex Subject** mechanism (§3.3) is the native way to express
this: one `sub_id` object with named members. The standard member names (`user`, `device`,
`session`, `application`, `tenant`, `org_unit`, `group`) don't quite fit an agent's
delegated-authority relationship, so this profile defines two custom members, which SSF §3.3
explicitly permits:

- **`principal`** — the human or organizational entity granting or holding ultimate
  accountability for the mandate.
- **`workload`** — the workload (agent) receiving or holding the mandate. Uses WISE's own
  `uri`/`wimse://` subject identifier format where applicable, for consistency with WISE where
  both profiles are deployed together.

```json
"sub_id": {
  "format": "complex",
  "principal": {
    "format": "email",
    "email": "procurement-lead@example.com"
  },
  "workload": {
    "format": "uri",
    "uri": "wimse://trust.example.com/workload/procurement-negotiator"
  }
}
```

**Complex Subject conformance:** SSF core permits Complex Subjects, but a profile that stays
silent on Receiver support can end up with a real interoperability gap — a Transmitter that
identifies subjects this way has no assurance a conforming Receiver will accept the event. This
profile writes the requirement explicitly rather than leaving it to core-spec silence:

- Receivers implementing `mandate-requested`, `mandate-denied`, or `mandate-granted` MUST be
  prepared to accept a Complex Subject. Receivers implementing only the Simple-Subject events
  (`mandate-rotated`, `mandate-revoked`, `mandate-violation-detected`, `mandate-executed`) are not
  required to.
- Such Receivers MUST NOT reject an event solely because its Subject Member is a Complex Subject,
  or because it carries a Subject Member name they do not recognize, and MUST be able to extract
  the `principal` member (this profile's anchor member, playing the role CAEP's `user` plays).
- Receivers MUST treat Subject Members absent from a Complex Subject as wildcards, per SSF §3.3.1
  — an absent `workload` member means "any workload," not "no workload."
- No `opaque`-format carve-out is currently needed: `principal` uses `email`, `workload` uses
  `uri`. Revisit if an opaque workload identifier is ever added.

Events that concern only the workload side of an already-established mandate (e.g.
`mandate-rotated`, `mandate-revoked`) may use a Simple Subject (just the `workload` identifier)
instead, consistent with how WISE's own Credential Lifecycle events are scoped.

---

## 4. Event Types

### 4.1. mandate-requested

**Event Type URI:** `.../event-type/mandate-requested`

Signals that a workload requested a mandate from a principal. Past-tense, as SSF events describe
facts that already occurred — SSF is a unidirectional notification framework, not a
request/response channel, so this event reports that a request was made, not the request itself
pending a synchronous answer. The approval/denial decision happens outside SSF and is reported
separately via `mandate-granted` or `mandate-denied`.

**Attributes:**

- **`mandate_type`** — REQUIRED. `root` or `child` (requested as a delegation from an existing
  parent mandate).
- **`parent_mandate_id`** — OPTIONAL. If `mandate_type` is `child`, the parent mandate being
  delegated from.
- **`scope_summary`** — OPTIONAL. Free-text description of the authority requested. Advisory
  only.
- **`event_timestamp`** — OPTIONAL.

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-098",
  "iat": 1700000000,
  "aud": "https://vendor.partner.example.net/mle",
  "sub_id": {
    "format": "complex",
    "principal": { "format": "email", "email": "procurement-lead@example.com" },
    "workload": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" }
  },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-requested": {
      "mandate_type": "root",
      "scope_summary": "Negotiate vendor contracts up to $50,000, Q3 procurement cycle"
    }
  }
}
```

### 4.2. mandate-denied

**Event Type URI:** `.../event-type/mandate-denied`

Signals that a requested mandate was not granted. The natural complement to `mandate-requested`,
closing the create/reject pair.

**Attributes:**

- **`reason`** — OPTIONAL. Why the request was denied (e.g. `insufficient_authority`,
  `policy_denied`, `duplicate_request`).
- **`event_timestamp`** — OPTIONAL.
- **`reason_admin`** — OPTIONAL, as defined in Common Optional Claims (§2).

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-099",
  "iat": 1700000000,
  "aud": "https://vendor.partner.example.net/mle",
  "sub_id": {
    "format": "complex",
    "principal": { "format": "email", "email": "procurement-lead@example.com" },
    "workload": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" }
  },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-denied": {
      "reason": "policy_denied",
      "reason_admin": { "en": "Requested scope exceeds delegation policy for this role" }
    }
  }
}
```

### 4.3. mandate-granted

**Event Type URI:** `.../event-type/mandate-granted`

Signals that a new mandate was issued to a workload by a principal.

**Attributes:**

- **`mandate_type`** — REQUIRED. `root` or `child`.
- **`mandate_id`** — OPTIONAL. Identifier for the mandate (e.g. a JWT `jti` value).
- **`parent_mandate_id`** — OPTIONAL. Identifier of the parent mandate, if `mandate_type` is
  `child`.
- **`scope_summary`** — OPTIONAL. Free-text; advisory only, not the authoritative scope
  definition.
- **`expiry`** — OPTIONAL. Expiration time of the mandate (NumericDate).
- **`event_timestamp`** — OPTIONAL.

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-100",
  "iat": 1700000000,
  "aud": "https://vendor.partner.example.net/mle",
  "sub_id": {
    "format": "complex",
    "principal": { "format": "email", "email": "procurement-lead@example.com" },
    "workload": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" }
  },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-granted": {
      "mandate_type": "root",
      "mandate_id": "mandate-2026-q3-0091",
      "scope_summary": "Negotiate vendor contracts up to $50,000, Q3 procurement cycle",
      "expiry": 1706745600
    }
  }
}
```

### 4.4. mandate-executed

**Event Type URI:** `.../event-type/mandate-executed`

Signals that a mandate was exercised, resulting in the issuance of a credential the workload uses
to carry that authority into an actual call or transaction. A mandate is a standing grant of
authority; a credential issued at execution time is what actually gets presented on the wire.

**Attributes:**

- **`mandate_id`** — OPTIONAL. Identifier of the mandate being executed.
- **`credential_type`** — REQUIRED. The type of credential issued as a result of execution.
  Possible values:
  - `opaque` — an opaque token.
  - `jwt` — a JSON Web Token.
  - `txn_token` — a Transaction Token, per `draft-ietf-oauth-transaction-tokens`.
  - Additional values MAY be defined by profiling specifications or private agreement.
- **`credential_id`** — OPTIONAL. Identifier of the issued credential (e.g. the Transaction
  Token's `txn` or `jti` value), for correlation.
- **`event_timestamp`** — OPTIONAL.

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-101",
  "iat": 1700000000,
  "aud": "https://vendor.partner.example.net/mle",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-executed": {
      "mandate_id": "mandate-2026-q3-0091",
      "credential_type": "txn_token",
      "credential_id": "txn:8675309-0042"
    }
  }
}
```

**Notes:**
- `credential_id` is deliberately compatible with SSF's own `txn` claim convention, so a
  `mandate-executed` event and the Transaction Token it produced can be correlated by a Receiver
  without needing Transaction-Token-specific knowledge.
- This event is expected to recur many times per mandate — one mandate may be exercised
  repeatedly before rotation or revocation.

### 4.5. mandate-rotated

**Event Type URI:** `.../event-type/mandate-rotated`

Signals that a workload's mandate was rotated — a new mandate replaces the previous one,
typically as part of routine renewal.

**Attributes:**

- **`previous_mandate_id`** — OPTIONAL.
- **`new_mandate_id`** — OPTIONAL.
- **`grace_period_end`** — OPTIONAL. NumericDate.
- **`event_timestamp`** — OPTIONAL.

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-102",
  "iat": 1700000000,
  "aud": "https://vendor.partner.example.net/mle",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-rotated": {
      "previous_mandate_id": "mandate-2026-q3-0091",
      "new_mandate_id": "mandate-2026-q3-0092",
      "grace_period_end": 1700003600
    }
  }
}
```

**Notes:**
- A Receiver that misses a timely rotation signal should treat the mandate's validity as
  *unknown*, not equivalent to revoked, and may request current status out-of-band.
- Where an active session runs under the mandate being rotated, that session is expected to be
  torn down as part of the rotation, using whatever session-management mechanism the deployment
  runs internally. This profile does not surface that session-level detail; `mandate-rotated` is
  the complete public signal.

### 4.6. mandate-revoked

**Event Type URI:** `.../event-type/mandate-revoked`

Signals that a workload's mandate was explicitly revoked before its natural expiry, while the
workload's underlying credential remains valid.

**Attributes:**

- **`mandate_id`** — OPTIONAL.
- **`revocation_type`** — REQUIRED. `direct` or `cascade`.
- **`cascade_root_mandate_id`** — REQUIRED when `revocation_type` is `cascade`. The `mandate_id`
  of the directly-revoked ancestor mandate.
- **`reason`** — OPTIONAL. `principal_revoked`, `scope_violation`, `constitutional_violation`,
  `irreversible_threshold`, `compromise`, `non_response`, `deadlock`. Additional values MAY be
  defined by profiling specifications or private agreement — this list is expected to evolve
  through working-group discussion.
- **`event_timestamp`** — OPTIONAL.
- **`reason_admin`** — OPTIONAL, as defined in Common Optional Claims (§2).

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-103",
  "iat": 1700000000,
  "aud": "https://vendor.partner.example.net/mle",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-revoked": {
      "mandate_id": "mandate-2026-q3-0092",
      "revocation_type": "cascade",
      "cascade_root_mandate_id": "mandate-2026-q3-0091",
      "reason": "principal_revoked",
      "reason_admin": { "en": "Q3 procurement budget reduced; vendor negotiation halted" }
    }
  }
}
```

**Notes:**
- `revocation_type: cascade` is where cascade-revocation semantics enter the event model — a
  Receiver seeing this value treats every descendant mandate as revoked, not just the named one.
- Structurally analogous to `credential-revoked` in WISE — the strongest, most directly
  comparable event in this profile.
- A `compromise`-reasoned revocation should trigger the same immediate Receiver action WISE
  requires for `credential-revoked (reason: compromise)` — no waiting for confirmation.
- The exposure window is bounded by whatever short-lived credential `mandate-executed` last
  issued (e.g. a Transaction Token's own short lifetime) — an already-issued credential isn't
  retroactively invalidated by this event; the point of enforcement is the *next*
  `mandate-executed`, which the issuing authority should refuse once revoked.

### 4.7. mandate-violation-detected

**Event Type URI:** `.../event-type/mandate-violation-detected`

Signals that a workload attempted, or was found to have taken, an action exceeding the scope of
its mandate. Advisory — structurally parallel to `credential-compromise`. May precede or
accompany `mandate-revoked` but does not require one.

**Attributes:**

- **`mandate_id`** — OPTIONAL.
- **`violation_type`** — OPTIONAL. `scope_exceeded` or `narrowing_violation` (a child mandate
  claiming authority broader than its parent).
- **`event_timestamp`** — OPTIONAL.
- **`reason_admin`** — OPTIONAL, as defined in Common Optional Claims (§2).

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-104",
  "iat": 1700000000,
  "aud": "https://vendor.partner.example.net/mle",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-violation-detected": {
      "mandate_id": "mandate-2026-q3-0092",
      "violation_type": "scope_exceeded",
      "reason_admin": { "en": "Attempted contract value of $75,000 exceeds mandate ceiling of $50,000" }
    }
  }
}
```

**Notes:**
- A Receiver should treat this as information to evaluate against its own policies, not a
  directive to enforce automatically — same posture WISE takes with `anomalous-behavior-detected`
  and `workload-vulnerability-status-changed`.

### 4.8. Summary: CRUD mapping

| Action | Event(s) |
|---|---|
| Create (request) | `mandate-requested` → `mandate-granted` \| `mandate-denied` |
| Update | `mandate-rotated` |
| Use | `mandate-executed` |
| Delete | `mandate-revoked` |
| Anomaly (outside CRUD) | `mandate-violation-detected` |

---

## 5. Security Considerations

### 5.1. Confidentiality, Replay, and Freshness

Inherited unchanged from WISE §4.1–4.2: all events MUST use TLS per [RFC9325], SHOULD be
encrypted with JWE [RFC7516] when crossing trust-domain boundaries, and Receivers MUST validate
`iat` and track `jti` to detect replay.

### 5.2. Delegation and Narrowing — what this profile does *not* enforce

**This profile does not itself enforce scope narrowing, delegation ceilings, or that a delegate
cannot present broader authority than it received.** `mandate-granted`'s `parent_mandate_id`
gives lineage *traceability*, not a verified narrowing guarantee — that enforcement is the job of
whatever mechanism actually issues the mandate. A Receiver MUST NOT treat receipt of a
`mandate-granted` event, by itself, as evidence that the granted scope is properly bounded
relative to its parent. This is a named external dependency, not a silent assumption.

**Where this profile does help:** `mandate-revoked`'s `revocation_type: cascade` gives a Receiver
a live, push-based signal that a parent mandate was revoked, rather than requiring it to
re-derive current status from a possibly-stale, previously-recorded delegation-chain entry. This
is a real strength relative to chain-only verification.

By default, authority does not propagate to further delegation hops automatically — each hop is
its own explicit `mandate-granted` event with its own scope. Re-scoping at every hop is expected,
consistent with the WIMSE architecture's treatment of agentic intermediaries.

### 5.3. Denial of Service

`mandate-executed` is expected to fire once per transaction and may recur at high frequency for
an active workload — an unbounded or malicious event volume from a compromised Transmitter is a
plausible resource exhaustion vector against a Receiver processing every event. Receivers SHOULD
apply rate limiting independent of any single event's validity.

For `mandate-revoked` with `revocation_type: cascade`, a Receiver that walks descendant mandates
in response SHOULD perform this cheaply-checkable field comparison before any expensive lookup or
policy evaluation.

### 5.4. Compromise Response

A `mandate-revoked` event with `reason: compromise` SHOULD trigger the same immediate Receiver
action WISE requires for `credential-revoked (reason: compromise)` — reject without waiting for
additional confirmation.

### 5.5. Relationship to Credential Freshness — the exposure window

A `mandate-revoked` event does not retroactively invalidate a credential already issued via a
prior `mandate-executed` event (e.g. an already-issued Transaction Token). The credential remains
valid for whatever lifetime it was issued with. The actual enforcement point is the *next*
`mandate-executed` request, which the issuing authority is expected to refuse once the mandate is
revoked. The resulting exposure window is bounded by the shortest-lived credential type in use —
this is a real, quantifiable bound a deployment can state, not a gap to hide.

### 5.6. Composition and Non-Sufficiency

This profile assumes an external mechanism (not defined here) provides the actual
authorization-object encoding, scope narrowing enforcement, and credential binding for a mandate
— MLE only signals lifecycle *events*, it does not itself constitute or verify authorization.
**A Receiver MUST NOT treat receipt of any MLE event, alone, as sufficient basis for a
consequential decision** — it is one input among several (identity, delegation chain, credential
verification, human authorization where applicable) that would need to be combined.

### 5.7. Known Gaps

- Scope narrowing (§5.2) is asserted by lineage, not verified by this profile.
- This profile does not address how a `principal` named in a Complex Subject came to hold the
  authority it's exercising when granting a mandate (e.g. that a named employee actually has
  procurement authority within their organization) — that root-of-authority question is out of
  scope and assumed established elsewhere.
- A Receiver that misses a `mandate-rotated` signal MUST NOT collapse the resulting indeterminate
  status into "valid" — treat as unknown, per §4.5's Notes. Stated here again because this is the
  single most likely failure mode for a Receiver implementing this profile.

## 6. Privacy Considerations

Unlike WISE's workload-only subject, this profile's Complex Subject explicitly carries a human
identity (`principal`), which raises privacy considerations WISE does not need to address.

**This profile does not assert:**
- the identity of a human or organization beyond what's explicitly named in the `principal`
  member for the specific event in question;
- that a mandated action was actually taken, or occurred as described — `mandate-executed`
  reports that a credential was issued as a result of executing a mandate, not that the
  downstream action it enabled succeeded, failed, or was appropriate;
- non-repudiation or an action receipt — a `mandate-executed` event is not evidence that a
  specific action occurred, only that a credential was minted at a point in time.

**Correlation risk:** binding a resolvable `principal` identifier (`email`/`iss_sub`) to a
`workload` identifier across every Mandate Lifecycle event creates a durable cross-event linkage
between a named human and everything that workload does under that mandate. Transmitters SHOULD
disclose the `principal` member only to Receivers that need it for the stated mandate purpose,
and SHOULD consider a Receiver-scoped or pairwise identifier for the `principal` member where a
globally stable identifier isn't required.

**Retention:** event payloads containing `principal` and `scope_summary` SHOULD be retained only
as long as needed for the stated audit/enforcement purpose, consistent with purpose limitation.
This profile does not define retention periods; deployments should state their own.

## 7. References

### 7.1. Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14,
RFC 2119, March 1997, <https://www.rfc-editor.org/rfc/rfc2119>.

[RFC5646] Phillips, A., Ed. and M. Davis, Ed., "Tags for Identifying Languages", BCP 47,
RFC 5646, September 2009, <https://www.rfc-editor.org/rfc/rfc5646>.

[RFC7516] Jones, M. and J. Hildebrand, "JSON Web Encryption (JWE)", RFC 7516, May 2015,
<https://www.rfc-editor.org/rfc/rfc7516>.

[RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14,
RFC 8174, May 2017, <https://www.rfc-editor.org/rfc/rfc8174>.

[RFC8417] Hunt, P., Ed., Jones, M., Denniss, W., and M. Ansari, "Security Event Token (SET)",
RFC 8417, July 2018, <https://www.rfc-editor.org/rfc/rfc8417>.

[RFC9325] Sheffer, Y., Saint-Andre, P., and T. Fossati, "Recommendations for Secure Use of TLS
and DTLS", BCP 195, RFC 9325, November 2022, <https://www.rfc-editor.org/rfc/rfc9325>.

[RFC9493] Backman, A., Ed., Scurtescu, M., and P. Jain, "Subject Identifiers for Security Event
Tokens", RFC 9493, December 2023, <https://www.rfc-editor.org/rfc/rfc9493>.

[SSF] Tulshibagwale, A., et al., "OpenID Shared Signals Framework Specification 1.0", 2025,
<https://openid.net/specs/openid-sharedsignals-framework-1_0.html>.

[CAEP] Cappalli, T. and A. Tulshibagwale, "OpenID Continuous Access Evaluation Profile 1.0",
2025, <https://openid.net/specs/openid-caep-1_0.html>.

[WISE] Lombardo, J., et al., "OpenID WISE Profile Specification 1.0", 2026,
<https://identitymonk.github.io/openid-wise/>.

[TXN-TOKENS] Tulshibagwale, A., Fletcher, G., and P. Kasselman, "OAuth 2.0 Transaction Tokens",
draft-ietf-oauth-transaction-tokens (work in progress).

### 7.2. Informative References

[RFC7519] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, May 2015,
<https://www.rfc-editor.org/rfc/rfc7519>.

[RISC] Scurtescu, M., et al., "OpenID RISC Profile Specification 1.0", 2025,
<https://openid.net/specs/openid-risc-1_0-final.html>.

[WIMSE-ARCH] Salowey, J., Rosomakho, Y., and H. Tschofenig, "Workload Identity in a Multi
System Environment (WIMSE) Architecture", 2026,
<https://www.ietf.org/archive/id/draft-ietf-wimse-arch-07.html>.

## 8. Open Questions for the Working Group

- **`hold` / `suspend`** — a possible eighth and ninth event, for temporarily pausing a mandate
  without fully revoking it. Not yet specified here; worth discussing whether it belongs in v1 or
  a later revision.
- **Namespace placement** — should this profile's event types live under a dedicated namespace,
  or is there value in coordinating more tightly with WISE's own namespace given the two are
  meant to be deployed together?
- **Relationship to Transaction Tokens** — `mandate-executed`'s `credential_type: txn_token` is
  intended as a concrete bridge to `draft-ietf-oauth-transaction-tokens`. Feedback on whether this
  is the right level of coupling, or whether it should be looser, would be useful.
