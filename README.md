# Mandate Lifecycle Events (MLE)

**A proposed Shared Signals Framework (SSF) profile — companion to, not an extension of, WISE**

**Author:** T. Sato, MyAuberge K.K.
**Date:** 27 August 2026; revised 14 October 2026 (aligned to WISE `-03`; disclosure control;
suspension) and 30 October 2026 (`txn` and Transactional Access Tokens; revocation closure) — see
Document History
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
- The Common Claims pattern (§2), matching WISE `-03`: `event_timestamp` as a common
  *mandatory* claim; `reason_admin`, `reason_user`, and `initiating_entity` as common optional
  claims with the localizable-object structure WISE inherits from CAEP; and `effective_at` as a
  common optional claim with WISE's semantics.
- WISE's rule for correlating SETs that arise from one occurrence through a shared `txn` claim,
  extended by §2.3 to SETs about a single transaction, where `txn` is the transaction's own
  identifier as [RFC8417] intends.
- The base SET/JWT envelope, `iss`/`aud`/`iat`/`jti` claims, and the confidentiality and
  replay/freshness requirements of WISE's Security Considerations (§5.1).

MLE is a companion profile, not a WISE profiling specification. WISE rules that apply to
"events defined by... profiling specifications" (notably its Compromise Response rule) therefore
do not reach MLE automatically; where MLE needs the same behavior, it states it itself (§5.4).

**Boundary with WISE's trust-level events.** WISE's `workload-degraded` reports the trust domain
authority's decision to reduce trust in a *workload* as a whole, affecting everything it does.
An MLE event reports a change to *one grant of authority* held by that workload, made by or on
behalf of the principal who granted it. A workload can be fully trusted while one of its
mandates is revoked, and degraded while its mandates are unchanged. Deployments SHOULD NOT use
either profile's events to stand in for the other's. The same holds for WISE's
`workload-disabled`/`workload-enabled` and MLE's `mandate-suspended`/`mandate-resumed`
(§4.7, §4.8): the first pair pauses a workload, the second one grant of authority.

What this profile adds, that WISE does not cover: mandate — as opposed to credential — lifecycle
events, and a `principal` Complex Subject member representing the human or organization the
mandate traces back to, which WISE's workload-only subject has no equivalent for. A deployment
running both profiles is expected to correlate a `mandate-executed` event here with the WISE
credential events describing the workload presenting that credential. Correlation between a
`mandate-executed` event and the token it reports uses the SET `txn` claim (§2.3); correlation
with WISE credential events beyond that remains a deployment-level integration question.

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
several possible types (opaque token, JWT, Transactional Access Token, Transaction Token), and
revoking the mandate does not
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

## 2. Common Claims

Common claims are omitted from the per-event attribute lists in §4 to avoid repetition.

### 2.1. Common Mandatory Claim

Every MLE event payload MUST include:

- **`event_timestamp`** — REQUIRED. A JSON number containing a NumericDate [RFC7519] that
  identifies when the event occurred; for an event reporting a decision or detection, when the
  decision was made or the condition detected. It is a member of the individual event payload,
  not a top-level SET claim, and may differ from the SET's `iat` and from `effective_at`. This is
  the same definition WISE `-03` adopts. Receivers rely on it to order state changes for the
  same mandate (§5.8).

### 2.2. Common Optional Claims

Unless stated otherwise, any event defined in this profile MAY include the following common
optional claims. The first three are defined in Section 2 of [CAEP] and reused here in the same
form WISE reuses them; `effective_at` is defined as in [WISE]:

- **`reason_admin`** — OPTIONAL. A localizable administrative message intended for logging and
  auditing. Its value is a JSON object containing one or more key/value pairs, where each key is
  a BCP 47 [RFC5646] language tag and each value is the locale-specific message.
- **`reason_user`** — OPTIONAL. A localizable, user-facing message, following the same JSON
  object structure as `reason_admin`.
- **`initiating_entity`** — OPTIONAL. A JSON string describing what triggered the event: one of
  `admin`, `user`, `policy`, or `system`.
- **`effective_at`** — OPTIONAL. A JSON number containing a NumericDate identifying when the
  change described by the event takes effect. A member of the event payload, not a top-level SET
  claim. It MAY be earlier than, equal to, or later than the SET's `iat`. If omitted, the change
  MUST be treated as effective as of the SET's `iat`, and a Receiver processing the SET at or
  after that time MUST apply the event-specific processing requirements immediately on receipt.
  It does not override event-specific processing requirements. A future `effective_at` on
  `mandate-revoked` expresses a scheduled revocation (e.g. "authority ends at quarter close")
  without a separate event type.

When an event in this profile includes `reason_admin` or `reason_user`, the claim MUST use the
localizable JSON object structure defined above rather than a plain string. The following is a
non-normative example:

```json
"reason_admin": {
  "en": "Q3 procurement budget reduced; vendor negotiation halted",
  "de": "Q3-Beschaffungsbudget reduziert; Lieferantenverhandlung ausgesetzt"
}
```

### 2.3. Transaction Identifier (`txn`) and Correlating Related Events

[RFC8417] §2.2 defines `txn` as an OPTIONAL transaction identifier used to correlate multiple
related JWTs, and states that it can be used both in SETs and in JWTs that are not SETs. OAuth
Transaction Tokens [TXN-TOKENS] and Transactional Access Tokens [TXN-AT] define their own `txn`
claim by reference to that section. It is one claim with one meaning: an MLE SET and the token a
mandate produced can carry the same `txn`, and a Receiver can correlate them without any
knowledge specific to either token format. (Earlier revisions of this profile treated the SET
`txn` and a token's `txn` as unrelated claims that merely shared a name. That was wrong and is
withdrawn.)

A SET carries a single `txn` value. Transmitters choose it by the scope of the event:

- **Transaction-scoped events** — `mandate-executed`, and `mandate-violation-detected` when it
  concerns one transaction: the `txn` of the credential the event concerns, as the Receiver sees
  it. For a Transactional Access Token this is the per-audience value issued for the Receiver's
  audience ([TXN-AT] §3.3).
- **Occurrence-scoped events** — all other events defined here, except `mandate-revocation-enforced`:
  one value per underlying occurrence, shared by every SET that occurrence produces for a given
  Receiver, across MLE and WISE event types. One occurrence may produce several SETs: a cascade
  revocation or suspension produces one event per affected mandate, and a compromise may produce a
  WISE `credential-revoked` alongside MLE `mandate-revoked` events. This is the rule WISE `-03`
  adopts for its own events. One occurrence can affect many transactions, so no token `txn`
  applies here.
- **Acknowledgements** — `mandate-revocation-enforced` (§4.10) carries the `txn` of the
  `mandate-revoked` SET it acknowledges, exactly as that Receiver received it.

**Per-audience values.** A value that is identical across Receivers lets Receivers in different
organizations link their records ([RFC8417] §6). Transmitters SHOULD derive occurrence-scoped
`txn` values per audience. One acceptable construction, following [TXN-AT] §7.6, is
`txn = BASE64URL(HMAC-SHA-256(K_txn, occurrence_id || UTF8(aud)))`, where `K_txn` is a Transmitter
secret used only for this purpose. For the same reason, Transmitters SHOULD use a per-audience
`mandate_id` where a globally stable identifier is not required, applying the same derivation to
every event sent to a given Receiver.

**One event per SET.** [RFC8417] §2.2 does not allow the `events` claim to carry independent
logical events. Cascade descendants, and a WISE event paired with MLE events, are separate SETs
correlated by `txn`, never one SET with several event members.

**Join key.** Because `mandate-executed` carries both the minted token's `txn` and the
`mandate_id`, a Receiver that receives it can keep an index from `txn` to `mandate_id`. When a
later `mandate-revoked` or `mandate-suspended` names that `mandate_id` (or, for a cascade, that
`cascade_root_mandate_id`), the Receiver knows which in-flight tokens it covers and can stop
honoring them before they expire. This needs no change to the token format. The alternative, an
authorization server asserting a mandate reference inside the Transactional Access Token, is an
open question (§8).

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
  accountability for the mandate. Any Subject Identifier format [RFC9493] MAY be used. A
  Receiver-scoped (pairwise) `opaque` identifier is RECOMMENDED whenever the Receiver does not
  need to resolve the principal to a real-world identity (§6); `email` and `iss_sub` are for
  Receivers that do.
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

The same subject as it would be sent to a Receiver that needs to correlate events about the
principal but not identify them:

```json
"sub_id": {
  "format": "complex",
  "principal": {
    "format": "opaque",
    "id": "pw-7f3c9a1e-vendor-partner"
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
  (`mandate-rotated`, `mandate-revoked`, `mandate-suspended`, `mandate-resumed`,
  `mandate-violation-detected`, `mandate-executed`, `mandate-revocation-enforced`,
  `mandate-revocation-closure`) are not required to.
- Such Receivers MUST NOT reject an event solely because its Subject Member is a Complex Subject,
  or because it carries a Subject Member name they do not recognize, and MUST be able to extract
  the `principal` member (this profile's anchor member, playing the role CAEP's `user` plays).
- Receivers MUST treat Subject Members absent from a Complex Subject as wildcards, per SSF §3.3.1
  — an absent `workload` member means "any workload," not "no workload."
- Such Receivers MUST accept the `principal` member in at least the `email`, `iss_sub`, and
  `opaque` formats. (Earlier drafts assumed `email` only. Mandate formats commonly identify the
  principal by an internal identifier that is not an email address, and the pairwise identifiers
  recommended in §6 are `opaque` by nature.) An `opaque` principal is meaningful only within the
  stream it was issued for; Receivers MUST NOT assume it matches identifiers in other streams.

Events that concern only the workload side of an already-established mandate (e.g.
`mandate-rotated`, `mandate-revoked`, `mandate-suspended`) may use a Simple Subject (just the `workload` identifier)
instead, consistent with how WISE's own Credential Lifecycle events are scoped.

---

## 4. Event Types

Examples for events whose default disclosure class is `internal` (§4.13.1) are addressed to an
internal policy decision point; examples for `relying` events are addressed to an external
relying party (the vendor contract system of §1).

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
- **`scope_digest`** — OPTIONAL. Digest of the request as recorded by the authority, per §4.13.3.
- **`scope_summary`** — OPTIONAL. Free-text description of the authority requested. Advisory
  only, and restricted by §4.13.2: it MUST NOT be sent outside the `internal` disclosure class
  unless the disclosure policy for that Receiver permits it.

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-098",
  "iat": 1700000000,
  "aud": "https://pdp.trust.example.com/mle",
  "sub_id": {
    "format": "complex",
    "principal": { "format": "email", "email": "procurement-lead@example.com" },
    "workload": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" }
  },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-requested": {
      "mandate_type": "root",
      "scope_digest": "sha-256:mVq2wGZ7k1tYc0x9Ld4hPj8sRb6NfAe3Uo5iKyTnHw0",
      "scope_summary": "Negotiate vendor contracts up to $50,000, Q3 procurement cycle",
      "event_timestamp": 1700000000
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
- **`reason_admin`** — OPTIONAL, as defined in Common Optional Claims (§2.2).

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-099",
  "iat": 1700000000,
  "aud": "https://pdp.trust.example.com/mle",
  "sub_id": {
    "format": "complex",
    "principal": { "format": "email", "email": "procurement-lead@example.com" },
    "workload": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" }
  },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-denied": {
      "reason": "policy_denied",
      "reason_admin": { "en": "Requested scope exceeds delegation policy for this role" },
      "event_timestamp": 1700000000
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
- **`scope_ref`** — OPTIONAL. URI from which an authorized Receiver can obtain the authoritative
  mandate (§4.13.3).
- **`scope_digest`** — OPTIONAL. Digest of the authoritative mandate artifact (§4.13.3). Lets a
  Receiver that already holds the mandate confirm exactly which version this event concerns,
  without the event disclosing its content.
- **`scope_summary`** — OPTIONAL. Free-text; advisory only, not the authoritative scope
  definition. Restricted to the `internal` disclosure class unless policy permits (§4.13.2).
- **`expiry`** — OPTIONAL. Expiration time of the mandate (NumericDate).

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-100",
  "iat": 1700000000,
  "aud": "https://pdp.trust.example.com/mle",
  "sub_id": {
    "format": "complex",
    "principal": { "format": "email", "email": "procurement-lead@example.com" },
    "workload": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" }
  },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-granted": {
      "mandate_type": "root",
      "mandate_id": "mandate-2026-q3-0091",
      "scope_ref": "https://authority.example.com/mandates/mandate-2026-q3-0091",
      "scope_digest": "sha-256:3Rk8YbLq0ZtW5vNcJx2Gp7HdSa9Mf1Ue4Ko6Ti_yBhE",
      "scope_summary": "Negotiate vendor contracts up to $50,000, Q3 procurement cycle",
      "expiry": 1706745600,
      "event_timestamp": 1700000000
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
  - `txn_access_token` — a Transactional Access Token [TXN-AT]: an access token audienced to a
    single resource server, carrying a per-audience `txn`. This is the expected value when the
    Receiver is outside the issuing trust domain.
  - `txn_token` — a Transaction Token [TXN-TOKENS]. A Txn-Token MUST NOT be accepted outside the
    trust domain named in its `aud`, so this value is meaningful only to Receivers inside that
    trust domain.
  - Additional values MAY be defined by profiling specifications or private agreement.
- **`credential_id`** — OPTIONAL. The issued credential's `jti`, for correlation with that
  specific token.

The SET's top-level `txn` claim carries the issued credential's `txn`, as the Receiver sees it
(§2.3). When the credential is a Transactional Access Token or a Transaction Token, Transmitters
MUST include it.

The example shows the event as sent to the resource server the token was issued for (§4.13.1):

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-101",
  "iat": 1700000000,
  "aud": "https://vendor.partner.example.net/mle",
  "txn": "k3JdQ9vX2mPz7LwR5tYb8A",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-executed": {
      "mandate_id": "mandate-2026-q3-0091",
      "credential_type": "txn_access_token",
      "credential_id": "0f8b6a4e-2d1c-4b7e-9a3f-6c5d4e3b2a10",
      "event_timestamp": 1700000000
    }
  }
}
```

**Notes:**
- The vendor's contract system receives the Transactional Access Token with `txn`
  `k3JdQ9vX2mPz7LwR5tYb8A` and this SET with the same value, and links the two without knowing
  anything specific to [TXN-AT].
- This event is the join key for later revocations and suspensions (§2.3). Transmitters MUST NOT
  sample or filter it on streams to Receivers that rely on it to match revocations to in-flight
  tokens; they MAY do so on streams used only for audit.
- The token can reach the resource server before this SET. Receivers MUST tolerate a `txn` they
  have not yet received an event for, and SHOULD NOT reject a token on that ground alone.
- This event is expected to recur many times per mandate — one mandate may be exercised
  repeatedly before rotation or revocation.

### 4.5. mandate-rotated

**Event Type URI:** `.../event-type/mandate-rotated`

Signals that a workload's mandate was replaced by a successor mandate. Mandates are treated as
immutable: any change to a mandate's scope — renewal, narrowing, or widening — is expressed as a
new mandate with a new `mandate_id` that supersedes the previous one, never as an edit in place.
This keeps every authority change visible as a distinct, auditable event, and means a Receiver
never has to reason about a mandate whose meaning shifted under the same identifier.

**Attributes:**

- **`previous_mandate_id`** — OPTIONAL.
- **`new_mandate_id`** — OPTIONAL.
- **`change_class`** — REQUIRED. How the successor's scope relates to the previous mandate's:
  - `renewal` — same scope, new validity period or new identifier only.
  - `narrowed` — the successor grants strictly less authority (fewer actions, lower limits,
    shorter validity, fewer delegation hops).
  - `expanded` — the successor grants more authority in at least one respect. A change that
    narrows some dimensions and widens others is `expanded`.
- **`scope_ref`**, **`scope_digest`** — OPTIONAL. For the *successor* mandate, as in §4.13.3.
- **`grace_period_end`** — OPTIONAL. NumericDate until which the previous mandate remains
  acceptable. MUST NOT be present when `change_class` is `narrowed`; a Receiver MUST ignore it
  if present on a `narrowed` event.

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
      "change_class": "narrowed",
      "scope_digest": "sha-256:Wc5pAz1QhL8tYe3Rn0Kg6VbXu2Mj9Do4Fs7Ii_NqTkU",
      "event_timestamp": 1700000000
    }
  }
}
```

**Processing by `change_class`:**

- **`narrowed`** is a tightening signal and is processed like a partial revocation: from
  `effective_at` (or immediately), the Receiver MUST stop accepting under the previous mandate
  anything the successor does not also authorize. Where the Receiver cannot tell which actions
  remain authorized (it does not hold the successor), it MUST treat the previous mandate as
  revoked and the successor as unknown until verified. The example above is a variant of the §1
  scenario: the budget is cut, and instead of withdrawing the mandate the principal narrows it.
- **`renewal`** carries no change of authority. Its default disclosure class is `internal`
  (§4.13.1); a relying party that needs continuity learns the successor's identifier when it is
  presented.
- **`expanded`** is a relaxing signal. A Receiver MUST NOT extend acceptance to the additional
  authority on the strength of this event alone; it MUST first obtain and verify the successor
  mandate through an authoritative channel (via `scope_ref`, or as presented by the workload),
  checking it against `scope_digest` where present. See §5.9.

**Notes:**
- A Receiver that misses a timely rotation signal should treat the mandate's validity as
  *unknown*, not equivalent to revoked, and may request current status out-of-band.
- Where an active session runs under the mandate being rotated, that session is expected to be
  torn down as part of the rotation, using whatever session-management mechanism the deployment
  runs internally. This profile does not surface that session-level detail; `mandate-rotated` is
  the complete public signal.
- Authority epochs (§5.10): a successor that required fresh authorization by the principal
  starts a new authority epoch, and the predecessor's authority is then closed as for a
  revocation. A successor issued without fresh authorization (typically `renewal`) continues the
  predecessor's epoch.

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
  `irreversible_threshold`, `compromise`, `non_response`, `deadlock`, `scheduled_rotation`,
  `operator_override`. Additional values MAY be defined by profiling specifications or private
  agreement — this list is expected to evolve through working-group discussion.
  - `scheduled_rotation` — the mandate is retired under a planned rotation or maintenance
    schedule. Where a successor mandate replaces it, the Transmitter SHOULD send
    `mandate-rotated` (§4.5) instead; this value is for retirement without a successor at that
    time.
  - `operator_override` — an administrator of the issuing trust domain revoked the mandate on
    its own authority, rather than on the principal's behalf or on a detected condition.
- **`suspension_id`** — OPTIONAL. Present when this revocation concludes a suspension (§4.7):
  the `suspension_id` of that suspension. For a cascade, each derived event carries the
  `suspension_id` of the suspension it concludes for its own mandate, where there is one.
- **`reason_admin`** — OPTIONAL, as defined in Common Optional Claims (§2.2).

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-103",
  "iat": 1700000000,
  "aud": "https://vendor.partner.example.net/mle",
  "txn": "Rk2vQ8sLmN4pZx7Tb1Ye9w",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-revoked": {
      "mandate_id": "mandate-2026-q3-0092",
      "revocation_type": "cascade",
      "cascade_root_mandate_id": "mandate-2026-q3-0091",
      "reason": "principal_revoked",
      "reason_admin": { "en": "Q3 procurement budget reduced; vendor negotiation halted" },
      "event_timestamp": 1700000000
    }
  }
}
```

**Notes:**
- `revocation_type: cascade` is where cascade-revocation semantics enter the event model — a
  Receiver seeing this value treats every descendant mandate as revoked, not just the named one.
- Structurally analogous to `credential-revoked` in WISE — the strongest, most directly
  comparable event in this profile.
- A `compromise`-reasoned revocation triggers immediate Receiver action without waiting for
  confirmation, per §5.4.
- A cascade produces one event per affected mandate; all of them SHOULD carry the same SET `txn`
  for a given Receiver (the occurrence value of §2.3), and a Transmitter SHOULD emit them only
  once the whole cascade is committed, so a Receiver never sees a revoked root with
  apparently-live descendants. The revocation's `txn` is never a token's `txn`, since one
  revocation can cover many transactions.
- `effective_at` (§2.2) in the future expresses a scheduled revocation. Until that time the
  mandate remains valid; a Receiver SHOULD NOT treat a scheduled revocation as immediate.
- A revocation of a suspended mandate, with or without `suspension_id`, ends the suspension:
  revocation is terminal (§5.8).
- The exposure window is bounded by whatever short-lived credential `mandate-executed` last
  issued (e.g. a Transactional Access Token, whose lifetime SHOULD NOT exceed 300 seconds per
  [TXN-AT] §3.5) — an already-issued credential isn't retroactively invalidated by this event;
  the point of enforcement is the *next* `mandate-executed`, which the issuing authority should
  refuse once revoked (for [TXN-AT], with the `transaction_denied` error).
- A Receiver that keeps the `txn` → `mandate_id` index of §2.3 can close the window earlier, by
  refusing in-flight tokens whose `txn` maps to the revoked mandate or to a descendant of
  `cascade_root_mandate_id`.
- **Pending effects.** After receiving this event, a Receiver MUST NOT commit any pending effect
  (queued work, a scheduled or retried operation, a delayed side effect) that is attributable to
  the revoked mandate or, for a cascade, to any descendant of `cascade_root_mandate_id`, unless it
  has been independently reauthorized under a different mandate. Effects that became irreversible
  before receipt are not reversed by this event (§5.10).
- Sending this event, and its successful delivery, do not show that the revocation has taken
  effect. A Transmitter MUST NOT report a revocation as complete on that basis alone; see
  `mandate-revocation-enforced` (§4.10) and §5.10.

### 4.7. mandate-suspended

**Event Type URI:** `.../event-type/mandate-suspended`

Signals that a workload's mandate has been suspended: it MUST NOT be exercised until the
suspension is lifted, but it has not been revoked. A suspension lets the issuing authority stop
a mandate immediately on information it cannot yet confirm — typically a report from outside
the issuing trust domain that the mandate or its workload is compromised or misused — while the
decision to revoke stays with a party that has authority to make it. It is the mandate-level
counterpart of WISE's `workload-disabled`.

A suspension ends in exactly one of three ways: `mandate-resumed` for the same `suspension_id`
(§4.8); `mandate-revoked` carrying that `suspension_id` (§4.6); or the mandate's natural expiry.
It has no timeout: a suspension that is never concluded keeps the mandate suspended until it
expires.

**Attributes:**

- **`mandate_id`** — OPTIONAL.
- **`suspension_id`** — REQUIRED. An identifier for this suspension, assigned by the issuing
  authority, unique per suspended mandate, and the same in every SET about this suspension sent
  to any Receiver. (A SET's `jti` cannot serve: it differs per Receiver.)
- **`suspension_type`** — REQUIRED. `direct` or `cascade`, with the same meaning as
  `revocation_type` in §4.6: a suspension applies to every descendant of the suspended mandate.
- **`cascade_root_mandate_id`** — REQUIRED when `suspension_type` is `cascade`.
- **`reason`** — OPTIONAL. One of:
  - `reported_compromise` — a party outside the issuing authority reported that the mandate,
    or the workload holding it, is compromised; the report is not yet confirmed.
  - `reported_violation` — a party outside the issuing authority reported that the workload
    acted outside the mandate; the report is not yet confirmed.
  - `pending_review` — the issuing authority, the principal, or an administrator paused the
    mandate pending a decision.

  Additional values MAY be defined as for §4.6. The value `compromise` MUST NOT be used on this
  event: it denotes a confirmed compromise (§5.4), and a confirmed compromise is a revocation.
- **`reason_admin`** — OPTIONAL, as defined in Common Optional Claims (§2.2), and restricted by
  §4.13.2.

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-105",
  "iat": 1700000000,
  "aud": "https://vendor.partner.example.net/mle",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "txn": "occ-5e21",
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-suspended": {
      "mandate_id": "mandate-2026-q3-0092",
      "suspension_id": "susp-0192a7c4",
      "suspension_type": "direct",
      "reason": "reported_compromise",
      "initiating_entity": "system",
      "event_timestamp": 1700000000
    }
  }
}
```

In the §1 scenario: a security vendor reports that the negotiating agent's credential appeared
in a leaked-secrets feed. The procurement authority cannot yet confirm it, so instead of
revoking it suspends the mandate and asks the procurement lead to decide. The vendor's contract
system stops accepting counter-offers at once.

**Processing:**

- A suspension is a tightening signal (§5.9). From `effective_at`, or immediately if absent, the
  Receiver MUST stop accepting actions, proposals, or credentials presented under the mandate
  and, for `suspension_type: cascade`, under every descendant mandate.
- A Receiver holding an in-progress transaction under the mandate — a pending countersignature,
  an authorized-but-unsettled payment, a queued irreversible operation — SHOULD NOT let it
  complete while the suspension lasts, as for compromise response (§5.4). It SHOULD hold the transaction rather than abort it where
  it can, since the suspension may be lifted; it MAY abort where holding is impractical.
- A Receiver MUST retain the suspended mandate's state, not discard it as it would a revoked
  mandate, so that a later `mandate-resumed` can restore it.
- A suspension is scoped to the mandate, exactly as §5.4 scopes compromise response. A
  `reported_compromise` suspension is not evidence that the workload's credential is
  compromised, and a Receiver SHOULD NOT reject the workload's credential or other mandates on
  the strength of it alone.
- A mandate may carry more than one unresolved suspension at once (for example, two independent
  reports). It is usable again only when every one of them has been resumed.

**Notes:**
- A cascade suspension produces one event per affected mandate, each with its own
  `suspension_id` and all sharing the SET `txn` (§2.3), emitted once the whole cascade is
  committed — as for cascade revocation (§4.6).
- A Receiver that misses a `mandate-suspended` sees only the later `mandate-resumed` or
  `mandate-revoked`. The first is harmless (§5.8); the second is processed as normal.

### 4.8. mandate-resumed

**Event Type URI:** `.../event-type/mandate-resumed`

Signals that a suspension of a workload's mandate has been lifted without revoking the mandate.
It restores the mandate exactly as it was before the suspension: it adds no authority and does
not extend the mandate's validity. It is the counterpart of WISE's `workload-enabled`.

**Attributes:**

- **`mandate_id`** — OPTIONAL.
- **`suspension_id`** — REQUIRED. The suspension being lifted.
- **`suspension_type`** — REQUIRED. `direct` or `cascade`, matching the suspension being lifted.
- **`cascade_root_mandate_id`** — REQUIRED when `suspension_type` is `cascade`.
- **`reason_admin`** — OPTIONAL, as for §4.7.

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-106",
  "iat": 1700003600,
  "aud": "https://vendor.partner.example.net/mle",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-resumed": {
      "mandate_id": "mandate-2026-q3-0092",
      "suspension_id": "susp-0192a7c4",
      "suspension_type": "direct",
      "initiating_entity": "user",
      "event_timestamp": 1700003600
    }
  }
}
```

**Processing:**

- `mandate-resumed` is a relaxing signal (§5.9). It lifts only the suspension it names; it
  never lifts a different suspension and never restores a revoked or expired mandate.
- When the lifted suspension's `reason` was `reported_compromise`, the Receiver MUST NOT resume
  acceptance on the strength of this event alone. It MUST first confirm the mandate's current
  status with the issuing authority through an authenticated channel — for example the
  `scope_ref` endpoint (§4.13.3), which, where it is offered, SHOULD report a mandate's
  suspensions and revocation alongside the artifact. For other reasons the Receiver SHOULD
  confirm in the same way, and MAY resume on the event alone when its stream from the
  Transmitter is configured as authoritative for this mandate's status.
- Until resumption takes effect, the mandate remains suspended; a failure to confirm leaves it
  suspended, never resumed.

**Notes:**
- Who may lift a suspension is a matter for the issuing authority, and it may be narrower than
  who may suspend or revoke. A deployment may, for example, let a delegate of the principal
  suspend or revoke a mandate but reserve resumption to the principal and administrators, so
  that a right to end authority never becomes a right to restore it. `initiating_entity`
  reports which kind of party lifted the suspension.
- A suspension concluded by revocation produces no `mandate-resumed`; the `mandate-revoked`
  event carries the `suspension_id` instead (§4.6).

### 4.9. mandate-violation-detected

**Event Type URI:** `.../event-type/mandate-violation-detected`

Signals that a workload attempted, or was found to have taken, an action exceeding the scope of
its mandate. Advisory — structurally parallel to WISE's `credential-compromised`. May precede or
accompany `mandate-revoked` but does not require one.

**Attributes:**

- **`mandate_id`** — OPTIONAL.
- **`violation_type`** — OPTIONAL. `scope_exceeded` or `narrowing_violation` (a child mandate
  claiming authority broader than its parent).
- **`reason_admin`** — OPTIONAL, as defined in Common Optional Claims (§2.2).

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
      "reason_admin": { "en": "Attempted contract value of $75,000 exceeds mandate ceiling of $50,000" },
      "event_timestamp": 1700000000
    }
  }
}
```

**Notes:**
- A Receiver should treat this as information to evaluate against its own policies, not a
  directive to enforce automatically — same posture WISE takes with `anomalous-behavior-detected`
  and `workload-vulnerability-status-changed`.

### 4.10. mandate-revocation-enforced

**Event Type URI:** `.../event-type/mandate-revocation-enforced`

Signals that a Receiver of a `mandate-revoked` event has applied it at its own enforcement points,
or could not. This event travels in the opposite direction to the others: the Receiver of the
revocation is its Transmitter, and the issuer of the revoked mandate is its Receiver, over a
separate SSF stream the issuer configures for this purpose. It turns a revocation from a
notification into something the issuer can track to completion (§5.10).

A Receiver that accepts `mandate-revoked` SHOULD send this event for each `mandate-revoked` SET it
receives, once its enforcement for that SET has reached a final state.

**Attributes:**

- **`mandate_id`** — REQUIRED. The `mandate_id` from the `mandate-revoked` SET being acknowledged,
  exactly as received (including any per-audience form, §2.3).
- **`acknowledged_jti`** — REQUIRED. The `jti` of the `mandate-revoked` SET being acknowledged.
- **`enforcement_status`** — REQUIRED. One of:
  - `enforced` — every enforcement point within the declared `scope` refuses the revoked authority.
  - `partial` — some enforcement points do; others are known and unresolved.
  - `failed` — enforcement could not be applied.
  - `not_applicable` — the Receiver holds no state, tokens, or pending work for this mandate.
- **`pending_effects`** — REQUIRED. What happened to work admitted before the revocation:
  `none`, `cancelled`, `fenced` (blocked at commit), or `unresolved`.
- **`scope`** — OPTIONAL. The classes of consequential effect the status covers, for example
  `["api", "queue", "storage", "payment"]`. Coarse classes only (§6).
- **`reason_admin`** — OPTIONAL. Why enforcement is `partial` or `failed`.

`event_timestamp` (§2.1) is when the final state was reached, by the Receiver's clock. The SET's
`txn` MUST equal the `txn` of the `mandate-revoked` SET being acknowledged (§2.3). Its `sub_id` is
the `workload` subject of that SET.

```json
{
  "iss": "https://vendor.partner.example.net/",
  "jti": "ack-7731",
  "iat": 1700000004,
  "aud": "https://authority.example.com/mle-ack",
  "txn": "Rk2vQ8sLmN4pZx7Tb1Ye9w",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-revocation-enforced": {
      "mandate_id": "mandate-2026-q3-0092",
      "acknowledged_jti": "evt-103",
      "enforcement_status": "enforced",
      "pending_effects": "fenced",
      "scope": ["api", "queue"],
      "event_timestamp": 1700000003
    }
  }
}
```

**Notes:**
- `enforced` makes a claim about the Receiver's own enforcement points only. It says nothing
  about systems the Receiver does not control, and the issuer MUST NOT read it that way.
- A Receiver that does not implement this event is not non-conforming. Its silence makes the
  closure status `unknown` or `partial` (§5.10), which is the correct outcome when nothing has
  been confirmed.
- The same event MAY acknowledge a `mandate-suspended`, with `acknowledged_jti` naming that SET;
  a deployment that does so tracks suspension enforcement the same way.

### 4.11. mandate-revocation-closure

**Event Type URI:** `.../event-type/mandate-revocation-closure`

OPTIONAL. Sent by the issuer of a revoked mandate to Receivers that need evidence that a
revocation is complete, such as the principal's organization or an auditor. It is a closure
receipt in the sense of [WATTS-CLOSURE], encoded as a SET.

**Attributes:**

- **`mandate_id`** — REQUIRED.
- **`closure_status`** — REQUIRED. One of `propagating`, `closed`, `partial`, `failed`,
  `unknown`, with the meanings in §5.10.
- **`receivers_notified`** — OPTIONAL. Number of Receivers sent the `mandate-revoked` event.
- **`receivers_enforced`** — OPTIONAL. Number that acknowledged `enforced` or `not_applicable`.
- **`unresolved`** — OPTIONAL. Opaque, per-audience identifiers for Receivers that acknowledged
  `partial` or `failed` or did not acknowledge within the closure budget.
- **`closure_budget`** — OPTIONAL. The budget in seconds the issuer applied (§5.10).
- **`evidence_digest`** — OPTIONAL. A digest of the acknowledgements and audit records the status
  rests on, so that it can be checked later without disclosing them in the event.

`event_timestamp` (§2.1) is when the status was determined. The SET's `txn` is the occurrence
value of the revocation decision (§2.3). An issuer MAY send this event more than once for the same
revocation as the status changes, for example from `propagating` to `closed`; under §5.8 each
later event supersedes the earlier one for that Receiver.

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-110",
  "iat": 1700000060,
  "aud": "https://audit.trust.example.com/mle",
  "txn": "Vb3sN8qLwD1xRt6Yk0Pe4g",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-revocation-closure": {
      "mandate_id": "mandate-2026-q3-0092",
      "closure_status": "closed",
      "receivers_notified": 3,
      "receivers_enforced": 3,
      "closure_budget": 300,
      "evidence_digest": "sha-256:p8Jc2Ld7Qw0Hs5Nb3Yt9Ra1Ve6Ko4Mi_zUf2Gx7TqA",
      "event_timestamp": 1700000058
    }
  }
}
```

### 4.12. Summary: CRUD mapping

| Action | Event(s) |
|---|---|
| Create (request) | `mandate-requested` → `mandate-granted` \| `mandate-denied` |
| Update (replace with successor) | `mandate-rotated` with `change_class` `renewal` \| `narrowed` \| `expanded` |
| Use | `mandate-executed` |
| Pause / unpause | `mandate-suspended` → `mandate-resumed` \| `mandate-revoked` |
| Delete | `mandate-revoked` |
| Confirm deletion | `mandate-revocation-enforced` (Receiver → issuer) → `mandate-revocation-closure` (issuer → principal, auditor) |
| Anomaly (outside CRUD) | `mandate-violation-detected` |

### 4.13. Disclosure and Content Control

An MLE event is a *signal about* a mandate, not the mandate itself. The authoritative content of
a mandate stays with the authority that issued it. What an event carries on the wire is an
identifier, a description of the change, and only as much content as the particular Receiver
needs. This section defines how a Transmitter controls that, at four levels: which events a
Receiver gets, which fields appear, how content is referenced rather than copied, and who decides.

#### 4.13.1. Disclosure Classes

Each event has a default disclosure class:

- **`internal`** — Receivers within the issuing trust domain (policy decision points, audit,
  the issuing authority's own systems).
- **`relying`** — additionally, Receivers that *rely on* the mandate's authority: any party that
  accepts actions, proposals, or credentials presented under that mandate (the vendor contract
  system of §1).

| Event | Default class | Rationale |
|---|---|---|
| `mandate-requested` | `internal` | Reveals intended activity before any authority exists. |
| `mandate-denied` | `internal` | Reveals internal policy decisions; no relying party exists yet. |
| `mandate-granted` | `internal` | Relying parties learn of a mandate when it is presented to them; broadcasting grants discloses business activity. |
| `mandate-executed` | `internal`, plus the audience of the credential | High-frequency; reveals activity patterns (§5.3). Also sent to the resource server a credential was issued for, about that credential only: that Receiver already holds the token, and needs the event as the join key for later revocations (§2.3). |
| `mandate-rotated` (`renewal`) | `internal` | No change of authority. |
| `mandate-rotated` (`narrowed`) | `relying` | Tightening; relying parties must stop accepting the removed authority. |
| `mandate-rotated` (`expanded`) | `internal` | Relaxing (§5.9); relying parties verify the successor when it is presented. |
| `mandate-revoked` | `relying` | The core purpose of this profile (§1). |
| `mandate-suspended` | `relying` | Tightening; relying parties must stop accepting at once. |
| `mandate-resumed` | `relying` | Relaxing, but relying parties that received the suspension need it to restore the mandate (§4.8). Sent only to Receivers that were sent the suspension. |
| `mandate-violation-detected` | `relying` | Relying parties of the affected mandate need it to evaluate pending actions. |
| `mandate-revocation-enforced` | — | Not delivered by the issuer: sent by a Receiver back to the issuer, on a stream the issuer configures with that Receiver (§4.10). |
| `mandate-revocation-closure` | `internal` | Closure evidence for the principal's organization and auditors; reveals which Receivers did not confirm (§6). |

A Transmitter MUST NOT deliver an event outside its default class unless the disclosure policy
for that Receiver (§4.13.4) permits it, and SHOULD deliver every `relying`-class event to every
Receiver it knows to be relying on the affected mandate. Within a class, a Transmitter SHOULD
deliver events only for subjects the Receiver has a stake in, using SSF stream subject
management, rather than every mandate the Transmitter knows about.

Delivery of event types to a stream is controlled through the SSF stream configuration
(`events_requested` / `events_delivered`). A Receiver requesting an event type does not entitle
it to that type: the Transmitter MUST omit from `events_delivered` any type the Receiver is not
entitled to under this section.

#### 4.13.2. Field-Level Minimization

Even within an entitled event, the Transmitter tailors the payload per Receiver:

- **`principal`**: send a pairwise `opaque` identifier (§3) unless the Receiver needs to resolve
  the principal's identity.
- **`scope_summary`** and free-text `reason_admin` / `reason_user`: these can carry business
  terms (limits, counterparties, budgets). They MUST NOT be sent to a Receiver outside the
  `internal` class unless the disclosure policy for that Receiver permits it. Structured fields
  (`reason`, `change_class`, `violation_type`) carry the information a relying party needs to act.
- **`scope_ref` / `scope_digest`**: may be sent to any entitled Receiver; they disclose nothing
  about content (§4.13.3).

Events carrying a `principal` member in a resolvable format, `scope_summary`, or free-text
reasons MUST be encrypted with JWE [RFC7516] to the specific Receiver when they cross a
trust-domain boundary — a strengthening of the general SHOULD in §5.1 for exactly the payloads
that carry content.

#### 4.13.3. Referencing Scope Instead of Copying It

- **`scope_digest`** — a digest of the authoritative mandate artifact, as
  `"<alg>:<base64url digest>"` (e.g. `sha-256:...`). It MUST be computed over the complete
  artifact as issued (for a JWT-encoded mandate, its full compact serialization), not over the
  scope fields alone: scope values such as limits or action names are low-entropy and could be
  recovered from a bare digest by guessing, whereas the complete artifact contains unpredictable
  values (its identifier and signature). A Receiver that holds a mandate compares digests to
  confirm which version an event concerns; a Receiver that does not hold it learns nothing.
- **`scope_ref`** — an `https` URI from which an authorized Receiver can obtain the
  authoritative mandate. Dereferencing MUST require the Receiver to authenticate, and the
  endpoint MUST apply the same disclosure policy as the event stream. The Receiver MUST verify
  the obtained artifact (signature, and `scope_digest` when present) before relying on it, and
  SHOULD fetch only from endpoints within the Transmitter's own trust domain. A Transmitter
  SHOULD omit `scope_ref` for Receivers not entitled to the content.

#### 4.13.4. Who Decides

Disclosure is decided by the party that granted the authority, not by the Transmitter's
convenience. The issuing authority defines a disclosure policy — for each mandate, or for a class
of mandates — stating which Receivers or Receiver classes may receive which events and fields.
The policy MAY travel with the mandate itself, so that a mandate carries its own rule for who may
learn of changes to it. This profile does not define the policy's encoding; it requires only that:

- the Transmitter enforces the applicable policy at both stream level (§4.13.1) and field level
  (§4.13.2);
- in the absence of a policy, the defaults in §4.13.1 and §4.13.2 apply;
- a policy may widen disclosure beyond the defaults, but MUST NOT suppress delivery of
  `relying`-class events to Receivers relying on the affected mandate. Withholding a revocation
  or narrowing from the parties who rely on the authority defeats the purpose of this profile.

---

## 5. Security Considerations

### 5.1. Confidentiality, Replay, and Freshness

Inherited unchanged from WISE's Security Considerations (Confidentiality; Replay and
Freshness): all events MUST use TLS per [RFC9325], SHOULD be encrypted with JWE [RFC7516] when
crossing trust-domain boundaries, and Receivers MUST validate `iat` and track `jti` to detect
replay.

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
apply rate limiting independent of any single event's validity. A Receiver that uses
`mandate-executed` as a join key (§2.3) SHOULD bound its `txn` → `mandate_id` index by the
lifetime of the credentials it indexes; entries older than the longest credential lifetime in use
can be dropped.

For `mandate-revoked` with `revocation_type: cascade`, a Receiver that walks descendant mandates
in response SHOULD perform this cheaply-checkable field comparison before any expensive lookup or
policy evaluation.

### 5.4. Compromise Response

This section states for MLE the behavior WISE `-03` requires of its own events; it is restated
rather than inherited because MLE is not a WISE profiling specification (§1.2).

Upon receiving any MLE event that carries a `reason` of `compromise` — regardless of event type,
including event types defined by future revisions of this profile — a Receiver SHOULD take
immediate action appropriate to the **affected mandate** without waiting for additional
confirmation: stop accepting actions, proposals, or credentials presented under that mandate
and, for `revocation_type: cascade`, under every descendant mandate.

The affected object is the mandate, not the workload. An MLE compromise signal does not by itself
indicate that the workload's credential is compromised, and a Receiver SHOULD NOT reject the
workload's credential or other mandates on the strength of an MLE event alone. Where the
workload's credential is also compromised, the Transmitter signals that separately with the
corresponding WISE event, correlated by `txn` (§2.3).

A compromise that the issuing authority has not confirmed — a report from another party — is
signaled with `mandate-suspended` and `reason: reported_compromise` (§4.7), not with
`compromise`. The Receiver stops accepting the mandate just as quickly, but the mandate is not
ended until a party with authority to revoke it decides. A Transmitter that sent `compromise`
on an unconfirmed report would let anyone able to make a plausible report terminate a
legitimate principal's authority.

Rejecting a mandate only takes effect at the next point the Receiver checks authority. A
Receiver that holds an in-progress transaction under the affected mandate — a pending
countersignature, an authorized-but-unsettled payment, a queued irreversible operation — SHOULD
abort or suspend it rather than letting it complete. This mirrors WISE's guidance to terminate
live connections, and matters more here: mandate revocation is often about preventing an
irreversible step (§1). This is best-effort, applicable to Receivers able to correlate the
mandate to in-flight work.

### 5.5. Relationship to Credential Freshness — the exposure window

A `mandate-revoked` event does not retroactively invalidate a credential already issued via a
prior `mandate-executed` event (e.g. an already-issued Transactional Access Token or Transaction
Token). The credential remains
valid for whatever lifetime it was issued with. The actual enforcement point is the *next*
`mandate-executed` request, which the issuing authority is expected to refuse once the mandate is
revoked. The resulting exposure window is bounded by the shortest-lived credential type in use —
this is a real, quantifiable bound a deployment can state, not a gap to hide. For Transactional
Access Tokens the bound is at most 300 seconds ([TXN-AT] §3.5). Receivers that keep the join-key
index of §2.3 can close it sooner.

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

### 5.8. Ordering of State Changes

SSF does not guarantee in-order delivery. A late `mandate-granted` or `mandate-rotated` arriving
after a `mandate-revoked` for the same mandate must not reinstate it. Receivers MUST evaluate
state changes for a given `mandate_id` in `event_timestamp` order and MUST discard an event
whose `event_timestamp` is older than the latest one already applied for that mandate.
`mandate-revoked` is terminal for its `mandate_id`: no later-arriving event for that identifier
restores it, whatever its timestamp. Authority after revocation is re-established only by a new
mandate with a new `mandate_id`.

Suspensions are matched by `suspension_id`, not only by mandate. A Receiver MUST record a
`mandate-resumed` even when it holds no matching suspension — the suspension may still be in
transit — and MUST then ignore a later-arriving `mandate-suspended` with that `suspension_id`.
A `mandate-resumed` never lifts any other suspension of the same mandate, whatever its
timestamp.

### 5.9. Tightening and Relaxing Signals

MLE events are asymmetric in risk. A *tightening* event — `mandate-revoked`, `mandate-suspended`,
`mandate-rotated` with `change_class: narrowed`, `mandate-violation-detected` — reduces what a
Receiver accepts; if it is wrong, the cost is a refused action. A *relaxing* event —
`mandate-granted`, `mandate-resumed`, or `mandate-rotated` with `change_class: expanded` —
increases what a Receiver might accept; if it is
wrong or forged, the cost is an unauthorized action, possibly an irreversible one.

The two are therefore processed differently:

- Tightening events SHOULD be acted on upon receipt of a valid SET, without first fetching the
  mandate (§5.4, §4.5).
- Relaxing events MUST NOT by themselves cause a Receiver to accept additional authority. The
  Receiver accepts authority only on verifying the authoritative mandate itself (§4.5, §4.13.3,
  §5.6). `mandate-resumed` restores authority the Receiver already held rather than adding new
  authority, so §4.8 sets a graduated rule: confirmation is REQUIRED after a reported
  compromise and RECOMMENDED otherwise. An attacker who controls a Transmitter, or a misconfigured one, can then at worst cause
  refusals, not unauthorized actions.

This mirrors the observation that, for any signal able to relax a prior restriction, a spurious
relaxation suppresses protection silently and so warrants more assurance than a spurious
tightening.

A `closed` status in `mandate-revocation-closure` is relaxing in the same sense: a party that
relies on it proceeds as if the revoked authority could no longer act. It is protected by the
integrity rules of §5.10.

### 5.10. Revocation Closure

[WATTS-CLOSURE] distinguishes a revocation request, the invalidation of authority, and
*revocation closure*: the condition that, within a declared scope, no remaining path from the
revoked authority can produce a new consequential effect. This profile adopts that distinction.

**Authority epochs.** The authority a mandate confers forms one authority epoch, from
`mandate-granted` until it is revoked, expires, or is superseded by a successor that required
fresh authorization from the principal (§4.5). A new mandate granted after a revocation is a new
epoch. Evidence that one epoch is closed MUST NOT be used as evidence about another.

**What signals establish.** Sending `mandate-revoked` puts a revocation into the *propagating*
state. Neither sending it nor its successful delivery (an SSF Push response, or a Poll
acknowledgement) establishes that any Receiver has stopped honoring the revoked authority. An
issuer MUST NOT report a revocation as closed on the basis of delivery alone.

**Closure states.** An issuer that tracks closure SHOULD use these states, matching
[WATTS-CLOSURE] §6:

| State | Meaning in this profile |
|---|---|
| `propagating` | `mandate-revoked` has been sent; acknowledgements are outstanding. |
| `closed` | The issuer's own issuance point refuses the mandate, and every Receiver sent the revocation has acknowledged `enforced` or `not_applicable` with `pending_effects` other than `unresolved`. |
| `partial` | At least one Receiver acknowledged `partial`, or reported `pending_effects: unresolved`. |
| `failed` | At least one Receiver acknowledged `failed`, or the closure budget expired with acknowledgements outstanding and the issuer treats that as failure. |
| `unknown` | Acknowledgements are missing and the issuer cannot otherwise determine the state. |

`partial`, `failed`, and `unknown` MUST NOT be treated as `closed`. A party that needs closure
before continuing a sensitive action SHOULD fail closed in any of them. `closed` always refers to
the declared scope: the issuer's own enforcement plus the Receivers it sent the revocation to. It
never implies closure in systems outside that set.

**Closure budget.** A deployment MAY declare a closure budget: the time it allows from the
revocation decision to closure. Where Transactional Access Tokens are in use, paths that no
Receiver acknowledges are still bounded by the token lifetime (at most 300 seconds per [TXN-AT]
§3.5), so the budget can be set from that bound. Issuers SHOULD measure the budget on their own
clock and SHOULD NOT compare timestamps from different Receivers as if they shared one.

**Pending effects.** Closure concerns new effects. Work admitted before the revocation but
committed after it is a new effect and is covered by the rule in §4.6. Effects that became
irreversible before a Receiver received the revocation are not reversed, and their existence does
not by itself mean closure failed.

**Integrity.** A forged `closed` status could lead a party to proceed as if revoked authority could
no longer act. `mandate-revocation-enforced` and `mandate-revocation-closure` SETs MUST be signed,
and an issuer MUST accept acknowledgements only on a stream it configured with that Receiver,
signed with keys published for that stream's Transmitter. An acknowledgement whose
`acknowledged_jti`, `mandate_id`, and `txn` do not match a `mandate-revoked` SET the issuer sent
to that Receiver MUST be rejected.

**Fan-in.** A large cascade produces one acknowledgement per Receiver per affected mandate.
Issuers SHOULD rate-limit acknowledgement streams and MAY aggregate by `txn`; aggregation MUST NOT
turn an outstanding or `partial` acknowledgement into `closed`.

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

**Content minimization:** the disclosure classes and field-level rules of §4.13 are this profile's
primary privacy control. In particular, mandates often encode commercial terms (spending limits,
counterparties, negotiation scope). Those terms belong in the authoritative mandate, reachable
through `scope_ref` by entitled Receivers, not in event payloads. A Transmitter that copies them
into `scope_summary` or free-text reasons for every Receiver turns the event stream into a feed of
the principal's business activity.

**Activity patterns:** even with minimized payloads, the timing and frequency of events — above
all `mandate-executed` — reveal what a workload and its principal are doing. Restricting those
events to the `internal` class (§4.13.1) is the main mitigation.

**Correlation through `txn` and `mandate_id`:** a value identical across Receivers lets
Receivers in different organizations link their records. Per-audience `txn` and `mandate_id`
(§2.3) avoid this, matching the per-audience `txn` of [TXN-AT] §3.3 and the guidance in
[RFC8417] §6. The Transmitter can still recompute every value for audit; it needs to retain
retired derivation keys for as long as it requires that capability.

**Acknowledgements reveal enforcement topology:** `mandate-revocation-enforced` tells the issuer
which kinds of systems a Receiver runs and how it handles pending work. Receivers SHOULD report
`scope` as coarse classes only, never host, queue, or service names. `mandate-revocation-closure`
SHOULD identify unresolved Receivers only by opaque, per-audience identifiers, so that the
principal or auditor receiving it does not learn the issuer's full list of relying parties
([WATTS-CLOSURE] §13).

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

[RFC7519] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, May 2015,
<https://www.rfc-editor.org/rfc/rfc7519>.

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

[WISE] Lombardo, J., Sneeggen, D., O'Dell, S., and P. Kasselman, "OpenID WISE Profile
Specification 1.0 - draft 03", OpenID Foundation Shared Signals Working Group, 2026,
<https://identitymonk.github.io/openid-wise/>.

[TXN-TOKENS] Tulshibagwale, A., Fletcher, G., and P. Kasselman, "Transaction Tokens",
draft-ietf-oauth-transaction-tokens-11 (work in progress), July 2026,
<https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/>.

[TXN-AT] Tulshibagwale, A., "Transactional Access Tokens",
draft-tulshi-oauth-transactional-access-tokens-00 (work in progress), September 2026,
<https://datatracker.ietf.org/doc/draft-tulshi-oauth-transactional-access-tokens/>.

### 7.2. Informative References

[RISC] Scurtescu, M., et al., "OpenID RISC Profile Specification 1.0", 2025,
<https://openid.net/specs/openid-risc-1_0-final.html>.

[WIMSE-ARCH] Salowey, J., Rosomakho, Y., and H. Tschofenig, "Workload Identity in a Multi
System Environment (WIMSE) Architecture", 2026,
<https://www.ietf.org/archive/id/draft-ietf-wimse-arch-07.html>.

[WATTS-CLOSURE] Watts, D., "Revocation Closure for Agentic Authorization Systems",
draft-watts-oauth-agent-revocation-closure-01 (work in progress), October 2026,
<https://datatracker.ietf.org/doc/draft-watts-oauth-agent-revocation-closure/>.

[CHEN-REVOKE] Chen, M. and L. Su, "OAuth 2.0 Agent Authorization Explicit Revocation",
draft-chen-oauth-agent-revocation-00 (work in progress), April 2026,
<https://datatracker.ietf.org/doc/draft-chen-oauth-agent-revocation/>.

## 8. Open Questions for the Working Group

- **Suspension status endpoint** — §4.8 requires a Receiver to confirm status before resuming
  after a reported compromise, and suggests the `scope_ref` endpoint report suspensions. Should
  this profile define that status response, or leave it to the mandate format?
- **Namespace and registry** — WISE `-03` establishes a "WISE Event Types" IANA registry
  (Specification Required) under its own base URI. Registering MLE events there would make MLE a
  WISE extension, which this profile is deliberately not (§1.2). The working assumption is a
  separate "MLE Event Types" registry under the `/secevent/mandate/` base URI, using the same
  registration policy and expert criteria as WISE's. Is that the right call, or is a shared
  registry with distinct prefixes preferable?
- **`mandate-rotated` naming** — with `change_class`, this event now covers any replacement of a
  mandate by a successor, including narrowing and widening, not only routine renewal. Would
  `mandate-superseded` be a clearer name?
- **Disclosure policy encoding** — §4.13.4 requires an issuer-defined disclosure policy but leaves
  its encoding out of scope. Is a common encoding worth standardizing (for example as a claim in
  the mandate token), or should it remain deployment-specific?
- **Relationship to Transactional Access Tokens** — [TXN-AT] separates durable consent and
  client authority from per-transaction tokens; this profile signals changes to the durable half.
  Two ways to link a revocation to in-flight tokens are possible: the Receiver-side `txn` →
  `mandate_id` index of §2.3, which needs no change to [TXN-AT], or an AS-asserted, per-audience
  mandate reference in the Transactional Access Token's `tctx`, which removes the dependency on
  `mandate-executed` delivery. Which should be primary, and should both be allowed? [TXN-AT]
  Appendix C also asks whether the AS should be able to end a transaction before its handle
  expires; `mandate-revoked` and `mandate-suspended` sent to the resource servers holding live
  tokens are one answer.
- **Who transmits** — [TXN-AT] has the AS evaluate policy for every token, so the AS is the
  natural Transmitter for `mandate-executed`. Where the mandate is managed elsewhere, the AS needs
  to receive MLE events itself. Should the profile say which party transmits which events?
- **Revocation closure** — `mandate-revocation-enforced` makes every Receiver of a revocation also
  a Transmitter, back to the issuer. Is that cost acceptable, or should acknowledgements be
  limited to Receivers that hold pending work or in-flight tokens? Should `closed` require an
  acknowledgement from every Receiver, or may an issuer declare a Receiver out of scope when its
  only remaining exposure is bounded by a short credential lifetime? And should the closure
  receipt stay in this profile, or move to a separate profile of [WATTS-CLOSURE] that other
  revocation mechanisms (for example [CHEN-REVOKE]) could also use?

## Document History

**30 October 2026 — `txn` and Transactional Access Tokens; revocation closure**

- §2.3 rewritten after re-reading [RFC8417] §2.2: the SET `txn` and a token's `txn` are the same
  claim, meant to correlate related JWTs, SET or not. The earlier statement that they were
  unrelated is withdrawn. `txn` now depends on the scope of the event (the token's `txn` for
  transaction-scoped events, a per-occurrence value otherwise), occurrence values and
  `mandate_id` SHOULD be derived per audience, and `mandate-executed` becomes the join key between
  a revocation and in-flight tokens.
- `mandate-executed` (§4.4): new `credential_type` `txn_access_token` for Transactional Access
  Tokens [TXN-AT]; `txn_token` limited to Receivers inside the issuing trust domain;
  `credential_id` is now the token's `jti`; the SET MUST carry the token's `txn`; no sampling on
  streams that use it as the join key. §4.13.1: also delivered to the credential's own audience.
- `mandate-revoked` (§4.6): pending-effects rule; sending or delivering the event is not evidence
  that it took effect; exposure window stated for [TXN-AT] (at most 300 seconds).
- New §4.10 `mandate-revocation-enforced` (Receiver → issuer acknowledgement) and §4.11
  `mandate-revocation-closure` (optional closure receipt), and new §5.10 Revocation Closure,
  adopting the closure model of [WATTS-CLOSURE]: authority epochs, closure states, closure budget,
  integrity, and fan-in. §4.5 notes when a rotation starts a new epoch.
- §5.3, §5.5, §5.9 and §6 updated accordingly. References: [TXN-TOKENS] updated to `-11`; added
  [TXN-AT], [WATTS-CLOSURE], [CHEN-REVOKE]. Open Questions: Transaction Tokens question replaced by
  Transactional Access Tokens, "who transmits", and revocation closure.
- Renumbered: the CRUD summary is now §4.12, and Disclosure and Content Control §4.13.

**14 October 2026 (third revision) — suspension, and reason values**

- New §4.7 `mandate-suspended` and §4.8 `mandate-resumed`, closing the `hold` / `suspend` open
  question. A suspension stops a mandate at once on information the issuing authority cannot yet
  confirm, without ending it. It is matched by a REQUIRED `suspension_id`, cascades like
  revocation, has no timeout, and ends by resumption, revocation, or expiry. Resumption is a
  relaxing signal that requires status confirmation after a reported compromise.
- `mandate-revoked`: new `reason` values `scheduled_rotation` and `operator_override`; new
  OPTIONAL `suspension_id` for a revocation that concludes a suspension.
- §5.4: unconfirmed compromise is signaled as a suspension with `reason: reported_compromise`,
  never as `compromise`. §5.8: ordering rules for suspensions. §5.9: suspension is tightening,
  resumption relaxing.
- §1.2 boundary extended to WISE `workload-disabled`/`workload-enabled`; §3, §4.10, §4.11.1
  updated for the new events.
- Renumbered: `mandate-violation-detected` is now §4.9, the CRUD summary §4.10, and Disclosure
  and Content Control §4.11.

**14 October 2026 (later) — disclosure and content control**

- New §4.9 (now §4.13): per-event default disclosure classes (`internal` / `relying`) enforced through SSF
  stream configuration and subject management; field-level minimization; `scope_ref` /
  `scope_digest` to reference the authoritative mandate instead of copying it; disclosure
  decided by the issuing authority's policy, which may widen but never suppress delivery of
  tightening events to relying parties.
- `mandate-requested` and `mandate-granted`: added `scope_digest` (and `scope_ref` on granted);
  `scope_summary` restricted to the `internal` class by default. Examples for internal-class
  events are now addressed to an internal policy decision point.
- `mandate-rotated`: mandates are immutable; added REQUIRED `change_class` (`renewal` /
  `narrowed` / `expanded`) with processing rules, successor `scope_ref` / `scope_digest`, and no
  grace period for narrowing. CRUD table updated.
- New §5.9: tightening vs. relaxing signals — relaxing events never grant authority on their own.
- §3: `principal` may use any RFC 9493 format; pairwise `opaque` RECOMMENDED; Receivers MUST
  accept `email`, `iss_sub`, and `opaque` (replacing the earlier "no opaque carve-out" line).
- §6: added content-minimization and activity-pattern considerations.
- Open Questions: renaming `mandate-rotated` to `mandate-superseded`; disclosure policy encoding.

**14 October 2026 — aligned to WISE `-03`**

- Made `event_timestamp` a Common Mandatory claim (§2.1), removed the per-event OPTIONAL listings,
  and added it to every example, matching WISE `-03`.
- Added `effective_at` as a Common Optional claim with WISE's semantics (§2.2); noted its use for
  scheduled revocation.
- Added a "Correlating Related Events" rule using the SET `txn` claim (§2.3), and separated it
  explicitly from a Transaction Token's `txn`, which `mandate-executed` previously conflated.
- Restated Compromise Response for MLE (§5.4) rather than relying on analogy: scoped to the
  affected mandate, not the workload credential, and added best-effort abort of in-flight
  transactions under a revoked mandate.
- Added §5.8, ordering of state changes per `mandate_id`, with `mandate-revoked` terminal.
- Added a boundary statement against WISE's `workload-degraded` (§1.2), and noted that WISE rules
  scoped to its profiling specifications do not apply to MLE automatically.
- Cascade revocation: one event per affected mandate, shared `txn`, emitted after the cascade
  commits (§4.6 Notes).
- Updated references to WISE `-03`'s event name `credential-compromised` and to its Security
  Considerations by section name; updated the [WISE] reference.
- Open Questions: `hold`/`suspend` now cites WISE's reversible pairs; the namespace question now
  addresses WISE's new IANA registry.

**27 August 2026** — initial review draft.
