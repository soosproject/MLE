# Mandate Lifecycle Events (MLE)

**A proposed Shared Signals Framework (SSF) profile — companion to, not an extension of, WISE**

**Author:** T. Sato, MyAuberge K.K.
**Date:** 27 August 2026; revised 14 October 2026 (aligned to WISE `-03`; disclosure control;
suspension), 19 November 2026 (relationship to OAuth, RAR and Transactional Access Tokens),
21 November 2026 (aligned to WISE `-04`) and 28 November 2026 (externally ordered changes) —
see Document History
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
- The Common Claims pattern (§2), matching WISE `-04`: `event_timestamp` as a common
  *mandatory* claim; `reason_admin`, `reason_user`, and `initiating_entity` as common optional
  claims with the localizable-object structure WISE inherits from CAEP; and `effective_at` as a
  common optional claim with WISE's semantics.
- WISE's rule for correlating SETs that arise from one occurrence through a shared `txn` claim
  (§2.3).
- The base SET/JWT envelope, `iss`/`aud`/`iat`/`jti` claims, and the confidentiality and
  replay/freshness requirements of WISE's Security Considerations (§5.1).

MLE is a companion profile, not a WISE profiling specification. WISE rules that apply to
"events defined by... profiling specifications" (notably its Compromise Response rule) therefore
do not reach MLE automatically; where MLE needs the same behavior, it states it itself (§5.4).

**Boundary with WISE's trust-level and policy events.** WISE's `workload-trust-level-change`
reports the trust domain authority's decision to move a *workload* as a whole to a different
trust level (`full`, `reduced`, `restricted`, `minimal`), affecting everything it does. An MLE
event reports a change to *one grant of authority* held by that workload, made by or on behalf of
the principal who granted it. A workload can be at `full` trust while one of its mandates is
revoked, and at `restricted` while its mandates are unchanged. Likewise, WISE's `policy-changed`
reports a change to a trust domain's issuance, posture-evaluation or validation policy, not to
any one grant. Deployments SHOULD NOT use either profile's events to stand in for the other's. The same holds for WISE's
`workload-disabled`/`workload-enabled` and MLE's `mandate-suspended`/`mandate-resumed`
(§4.7, §4.8): the first pair pauses a workload, the second one grant of authority.

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

### 1.4. Relationship to Other Specifications

MLE is a signaling layer. It does not define what a mandate is made of, how one is issued, or
how a credential is minted from one; other specifications do, and MLE is designed to sit on top
of them. This section states where MLE stands relative to each.

**Shared Signals profiles (CAEP, RISC, WISE).** All four use the same SSF transport, stream
management and SET envelope; they differ in subject. CAEP signals changes to a user's *session*,
RISC to a user's *account*, WISE to a *workload's credential, trust material and posture*, and
MLE to a *grant of authority* held by a workload. A mandate change is not expressible as a CAEP
`session-revoked` (revoking the agent's session would also end every other mandate it holds) or
as `token-claims-change` (which concerns one token, not a standing grant from which many tokens
are minted), and CAEP has no subject for the principal–workload pair or for parent/child
delegation. The boundary with WISE is stated in §1.2.

**OAuth grants and Rich Authorization Requests [RFC9396].** Where mandates are issued by an
OAuth authorization server, the natural mandate is the *grant*: the authority the resource owner
or client policy approved, expressed as granted `authorization_details` (and/or `scope`).
Grant Management for OAuth 2.0 [GRANT-MGMT] gives that grant an identifier (`grant_id`), which
a Transmitter can use as `mandate_id`, and a query/revoke API that Clients *pull*. MLE is the
*push* counterpart: it tells every party relying on the grant that it changed. Several RAR
properties shape how MLE is applied to grants:

- RAR §6: the AS checks, on every token request, that the underlying grant still allows the
  requested `authorization_details`. That check is the enforcement point MLE relies on in §5.5:
  once a mandate is revoked or suspended, the next `mandate-executed` is refused.
- RAR §6.1: there is no generic way to compare two `authorization_details` values; "more" and
  "less" are defined per type. `change_class` (§4.5) and `narrowing_violation` (§4.9) are
  therefore computed by the issuing authority using the mandate format's own comparison rules,
  never by the Receiver from the event.
- RAR §6 also lets a client obtain a token with *fewer* rights than the grant without changing
  the grant. Such a token is a narrower credential, not a narrowed mandate, and produces no
  `mandate-rotated`.
- RAR §7.1: the AS may enrich the granted `authorization_details` beyond what was requested, so
  a request digest (`mandate-requested`) and a grant digest (`mandate-granted`) are expected to
  differ.
- RAR §9.1 and §13: the AS filters `authorization_details` per audience and shares them on a
  need-to-know basis. MLE's disclosure rules (§4.11) apply the same principle to lifecycle events.

**Transaction Tokens [TXN-TOKENS] and Transactional Access Tokens [TXN-AT].** These are
credentials minted under a mandate, one per transaction, and are what `mandate-executed`
reports (§4.4). A Transactional Access Token is issued by the AS to one resource server after a
fresh policy decision, with a short lifetime (the current draft says it SHOULD NOT exceed 300
seconds); the resource server may exchange it for a Transaction Token inside its own trust
domain. In MLE terms, consent and client authority are the durable mandate and the tokens are
per-transaction credentials. Their short lifetime is what bounds the exposure window of §5.5,
and MLE is what reaches resource servers that hold such tokens when the authority behind them
changes. Neither token format has a notion of delegation lineage between grants; MLE's
`parent_mandate_id` and cascade semantics supply the signaling half of that, while narrowing
enforcement remains with the issuing mechanism (§5.2).

**Token Exchange [RFC8693].** Delegation to a sub-agent is commonly performed by token exchange
with an actor (`act`). Where the exchange creates a new standing grant rather than a single
token, that grant is a child mandate and is announced with `mandate-granted`
(`mandate_type: child`).

**Revocation and status mechanisms.** OAuth Token Revocation [RFC7009] lets a client ask the AS
to invalidate a token and, where applicable, its grant; proposals for agent-level cascade
revocation [CHEN-REVOCATION] and for revocation closure [WATTS-CLOSURE] extend that request side.
Token Status List [STATUS-LIST] lets a relying party *pull* the status of a token, including a
`SUSPENDED` state. MLE is complementary to all of them: it does not request a revocation and
does not replace a status check. It pushes the fact that a mandate's state changed to parties
that would otherwise only learn of it at their next pull, and it gives `mandate-resumed` a
defined place to confirm status (§4.8). A deployment can use a status list as that confirmation
channel.

**Delegation-revocation events and per-action approval.** A proposal for OAuth
[NANDAKUMAR-REVOCATION] defines a `delegation-revoked` SET whose subject is a single delegated
*token*, identified by its `iss` and `jti`. Each holder relays the event to the holders of tokens
it issued, and verifiers check chain status as a backstop. Its companion [PACE-AUTHZ] issues
single-use approval tokens for one approved action, described as a RAR `agent_action`. The two
efforts overlap with MLE on cascade revocation but differ in what they name. They name a token
chain; MLE names the standing grant from which tokens are minted. They also define no
suspension, resumption, rotation or disclosure classes. Where a mandate is itself carried as a
single delegated token, a Transmitter can name it in `mandate-revoked` with the same (`iss`,
`jti`) pair it would use in `delegation-revoked`, and both events SHOULD share a SET `txn`
(§2.3). Whether MLE should adopt that subject format directly is an open question (§8).

**Mandate formats.** Several efforts define what a mandate *contains*: the Agent Payments
Protocol [AP2] defines Intent, Cart and Payment Mandates as signed verifiable credentials; a
problem statement on verifiable human mandates [YOSSIF-MANDATE] sets requirements for binding
an agent's actions to constraints a human authorized; and deployments define their own signed
mandate tokens. MLE is neutral among them. The working definition in §1.3 is functional only —
a mandate is whatever standing grant of authority the issuing authority manages — and MLE
carries a mandate's identifier and digest, never its schema. Note that "mandate" is used
differently across these efforts: an AP2 Intent Mandate records what the user wants done (the
"what" of §1.3) as well as the bounds within which the agent may act unattended (the "may"); it
is the latter that MLE events concern.

**Emergency orders from public authorities.** Legislation has been proposed that would let a
public authority order the operator of an AI system to throttle, restrict, suspend or shut it
down. The proposed U.S. AI Kill Switch Act [HR9917], for example, would require a covered entity
to be able to suspend access "with respect to an account, user, or use pattern", and, upon an
order, to notify each operator or user of the order and of the extent to which they might be
affected, and to confirm to the authority that the order has been carried out. MLE does not implement any such
regime and is not specific to any jurisdiction. Where an order changes the authority held by
workloads, however, the parties relying on that authority need to learn of it the same way they
learn of any other mandate change; MLE is that channel. §4.12 states how an order is reflected
in MLE events, and §5.10 what evidence of delivery a Transmitter can keep.

### 1.5. Notational Conventions

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
  the same definition WISE `-04` adopts. Receivers rely on it to order state changes for the
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
  claim. It MAY be earlier than or equal to the SET's `iat`, and MUST NOT be later: a SET
  reports something that has already happened [RFC8417], and a future-dated change would leave
  every Receiver holding pending state that no event in this profile could cancel. An earlier
  `effective_at` says the change took effect before it was reported — for example, that a
  mandate's authority ended at the moment of a compromise rather than when it was detected — and
  a Receiver SHOULD review what it accepted under the mandate since then. If omitted, the change
  MUST be treated as effective as of the SET's `iat`, and a Receiver processing the SET at or
  after that time MUST apply the event-specific processing requirements immediately on receipt.
  It does not override event-specific processing requirements. A Receiver that receives an
  `effective_at` later than the SET's `iat` MUST treat it as equal to `iat`.
- **`order`** — OPTIONAL. Identifies an order, from an authority outside the issuing trust
  domain, that the event carries out (§4.12). A JSON object with the members:
  - `authority` — REQUIRED. A URI identifying the authority that issued the order.
  - `order_ref` — OPTIONAL. The identifier of the order as assigned by that authority. Subject
    to §4.11.2.

  The claim identifies the order; it never carries the order's content or any detail of the
  incident behind it. It is the Transmitter's assertion, not evidence of the order, and changes
  nothing in how a Receiver processes the event (§4.12).

  A change planned for a future time is not sent in advance. Where the planned change is the end
  of a mandate's authority (e.g. "authority ends at quarter close"), the issuing authority
  shortens the mandate's `expiry` and reports it with `mandate-rotated`, `change_class: narrowed`
  (§4.5) — a fact at the moment it is sent, which a later rotation can reverse. Any other planned
  change is held by the Transmitter and sent when it takes effect.

When an event in this profile includes `reason_admin` or `reason_user`, the claim MUST use the
localizable JSON object structure defined above rather than a plain string. The following is a
non-normative example:

```json
"reason_admin": {
  "en": "Q3 procurement budget reduced; vendor negotiation halted",
  "de": "Q3-Beschaffungsbudget reduziert; Lieferantenverhandlung ausgesetzt"
}
```

### 2.3. Correlating Related Events

One occurrence may produce several SETs: a cascade revocation or suspension produces one event per
affected mandate, and a compromise may produce a WISE `credential-revoked` alongside MLE
`mandate-revoked` events. A Transmitter SHOULD set the same value in the OPTIONAL SET `txn`
(transaction identifier) claim [RFC8417] on all SETs arising from the same occurrence, across
MLE and WISE event types, so a Receiver can recognize that they share a cause. This is the rule
WISE `-04` adopts for its own events.

The SET `txn` claim is unrelated to the `txn` claims of OAuth tokens, despite the shared name:
the `txn` of a Transaction Token [TXN-TOKENS], the transaction identifier a JWT access token may
carry [RFC9396, §9.1], and the `txn` of a Transactional Access Token [TXN-AT], which differs per
audience so that only the authorization server can correlate it across resource servers. MLE
carries such a token's identifier in `mandate-executed`'s `credential_id` (§4.4), never in the
SET `txn` claim.

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
  `mandate-violation-detected`, `mandate-executed`) are not required to.
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

Examples for events whose default disclosure class is `internal` (§4.11.1) are addressed to an
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
- **`scope_digest`** — OPTIONAL. Digest of the request as recorded by the authority, per §4.11.3.
- **`scope_summary`** — OPTIONAL. Free-text description of the authority requested. Advisory
  only, and restricted by §4.11.2: it MUST NOT be sent outside the `internal` disclosure class
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
  mandate (§4.11.3).
- **`scope_digest`** — OPTIONAL. Digest of the authoritative mandate artifact (§4.11.3). Lets a
  Receiver that already holds the mandate confirm exactly which version this event concerns,
  without the event disclosing its content.
- **`scope_summary`** — OPTIONAL. Free-text; advisory only, not the authoritative scope
  definition. Restricted to the `internal` disclosure class unless policy permits (§4.11.2).
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
  - `txn_token` — a Transaction Token [TXN-TOKENS].
  - `txn_at` — a Transactional Access Token [TXN-AT].
  - `access_token` — another OAuth 2.0 access token, including a JWT access token carrying
    `authorization_details` [RFC9396].
  - Additional values MAY be defined by profiling specifications or private agreement.
- **`credential_id`** — OPTIONAL. Identifier of the issued credential (e.g. the Transaction
  Token's `txn` or `jti` value), for correlation. For a credential whose identifier differs per
  audience, such as a Transactional Access Token's `txn`, a Transmitter MUST send each Receiver
  only the identifier issued for that Receiver's audience, so that `mandate-executed` does not
  let Receivers correlate transactions the authorization server deliberately kept apart.
- **`credential_expiry`** — OPTIONAL. Expiration time of the issued credential (NumericDate).
  Lets a Receiver compute the exposure window of §5.5 without holding the credential.

```json
{
  "iss": "https://authority.example.com/",
  "jti": "evt-101",
  "iat": 1700000000,
  "aud": "https://pdp.trust.example.com/mle",
  "sub_id": { "format": "uri", "uri": "wimse://trust.example.com/workload/procurement-negotiator" },
  "events": {
    "https://schemas.openid.net/secevent/mandate/event-type/mandate-executed": {
      "mandate_id": "mandate-2026-q3-0091",
      "credential_type": "txn_token",
      "credential_id": "txn:8675309-0042",
      "event_timestamp": 1700000000
    }
  }
}
```

**Notes:**
- `credential_id` carries the issued credential's own identifier — for a Transaction Token, its
  `txn` or `jti` value — so a Receiver holding that token can match it to this event. This is
  not the SET-level `txn` claim used to correlate SETs (§2.3); the two only share a name.
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

  The issuing authority computes `change_class` using the comparison rules of the mandate's own
  format; there is no format-independent comparison (for OAuth grants, see [RFC9396], §6.1).
  An authority that cannot establish that the successor is no broader than its predecessor MUST
  report `expanded`, so that the Receiver verifies the successor before relying on it (§5.9).
- **`scope_ref`**, **`scope_digest`** — OPTIONAL. For the *successor* mandate, as in §4.11.3.
- **`expiry`** — OPTIONAL. Expiration time of the *successor* mandate (NumericDate). REQUIRED
  when the rotation's only change is an earlier expiry, so that a Receiver that does not hold the
  successor still learns when authority ends (§2.2).
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
  (§4.11.1); a relying party that needs continuity learns the successor's identifier when it is
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
  - `external_order` — the mandate was revoked to carry out an order from an authority outside
    the issuing trust domain. The event MUST carry the `order` claim (§2.2). Because orders can
    be reconsidered or overturned, and revocation is terminal (§5.8), a Transmitter SHOULD use
    `mandate-suspended` with the same reason instead, unless the order itself ends the authority
    permanently (§4.12).
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
  (§2.3), and a Transmitter SHOULD emit them only once the whole cascade is committed, so a
  Receiver never sees a revoked root with apparently-live descendants.
- `mandate-revoked` is never scheduled: `effective_at` (§2.2) can only place the revocation at
  or before the SET's `iat`. A planned end of authority is expressed by shortening the mandate's
  `expiry` (§4.5), which can still be reversed; a revocation cannot (§5.8).
- A revocation of a suspended mandate, with or without `suspension_id`, ends the suspension:
  revocation is terminal (§5.8).
- The exposure window is bounded by the longest-lived credential still outstanding under the
  mandate (e.g. a Transaction Token's own short lifetime) — an already-issued credential isn't
  retroactively invalidated by this event; the point of enforcement is the *next*
  `mandate-executed`, which the issuing authority should refuse once revoked.

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

The issuing authority SHOULD conclude every suspension it places with `mandate-resumed` or
`mandate-revoked` carrying its `suspension_id`, rather than leaving it to expiry, so that a
Receiver can tell a review still in progress from one that was dropped. A Receiver whose
suspension has been open longer than its local policy allows MAY confirm the mandate's status
with the issuing authority (through `scope_ref` or another status mechanism, §1.4), but MUST NOT
lift the suspension itself: unlike an advisory signal, a suspension is a directive, and only the
issuing authority can end it.

**Attributes:**

- **`mandate_id`** — OPTIONAL.
- **`suspension_id`** — REQUIRED. An identifier for this suspension, assigned by the issuing
  authority, unique per suspended mandate, and the same in every SET about this suspension sent
  to any Receiver. (A SET's `jti` cannot serve: it differs per Receiver.) It is a protocol
  identifier, needed because one mandate can carry several open suspensions; it MUST NOT be, or
  reveal, a reference from the authority's internal tools such as a ticket, case or
  change-request identifier. Pointers to such internal work, and any expected review date, belong
  in `reason_admin` (subject to §4.11.2) or in the document behind `scope_ref`.
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
  - `external_order` — an authority outside the issuing trust domain, with power to bind the
    issuing authority, ordered the mandate stopped. Unlike `reported_compromise`, this is not an
    unconfirmed report but a directive the issuing authority must follow. The event MUST carry
    the `order` claim (§2.2). The suspension is lifted when the order is lifted, withdrawn or
    overturned, and becomes a revocation if the order so requires (§4.12).

  Additional values MAY be defined as for §4.6. The value `compromise` MUST NOT be used on this
  event: it denotes a confirmed compromise (§5.4), and a confirmed compromise is a revocation.
- **`reason_admin`** — OPTIONAL, as defined in Common Optional Claims (§2.2), and restricted by
  §4.11.2.

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
- When the lifted suspension's `reason` was `reported_compromise` or `external_order`, the
  Receiver MUST NOT resume acceptance on the strength of this event alone. It MUST first confirm the mandate's current
  status with the issuing authority through an authenticated channel — for example the
  `scope_ref` endpoint (§4.11.3), which, where it is offered, SHOULD report a mandate's
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
- **`violation_type`** — OPTIONAL. One of:
  - `scope_exceeded` — an action beyond the mandate's scope.
  - `narrowing_violation` — a child mandate claiming authority broader than its parent.
  - `ended_mandate_use` — an action, or an attempt to obtain a credential, under a mandate that
    had been revoked, suspended or narrowed, or had expired, at the time of the action. Continued
    use after a mandate was stopped, for whatever reason, is the clearest evidence that a stop is
    not taking effect, and matters most when the stop carried out an order (§4.12).
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
- `ended_mandate_use` is often observed first by a Receiver, which sees the attempted action,
  rather than by the issuing authority. SSF streams flow from Transmitter to Receiver; how a
  Receiver reports such an observation back is outside this profile (§8).

### 4.10. Summary: CRUD mapping

| Action | Event(s) |
|---|---|
| Create (request) | `mandate-requested` → `mandate-granted` \| `mandate-denied` |
| Update (replace with successor) | `mandate-rotated` with `change_class` `renewal` \| `narrowed` \| `expanded` |
| Use | `mandate-executed` |
| Pause / unpause | `mandate-suspended` → `mandate-resumed` \| `mandate-revoked` |
| Delete | `mandate-revoked` |
| Anomaly (outside CRUD) | `mandate-violation-detected` |
| Externally ordered | any tightening event above, carrying `order` (§4.12) |

### 4.11. Disclosure and Content Control

An MLE event is a *signal about* a mandate, not the mandate itself. The authoritative content of
a mandate stays with the authority that issued it. What an event carries on the wire is an
identifier, a description of the change, and only as much content as the particular Receiver
needs. This section defines how a Transmitter controls that, at four levels: which events a
Receiver gets, which fields appear, how content is referenced rather than copied, and who decides.

#### 4.11.1. Disclosure Classes

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
| `mandate-executed` | `internal` | High-frequency; reveals activity patterns (§5.3). |
| `mandate-rotated` (`renewal`) | `internal` | No change of authority. |
| `mandate-rotated` (`narrowed`) | `relying` | Tightening; relying parties must stop accepting the removed authority. |
| `mandate-rotated` (`expanded`) | `internal` | Relaxing (§5.9); relying parties verify the successor when it is presented. |
| `mandate-revoked` | `relying` | The core purpose of this profile (§1). |
| `mandate-suspended` | `relying` | Tightening; relying parties must stop accepting at once. |
| `mandate-resumed` | `relying` | Relaxing, but relying parties that received the suspension need it to restore the mandate (§4.8). Sent only to Receivers that were sent the suspension. |
| `mandate-violation-detected` | `relying` | Relying parties of the affected mandate need it to evaluate pending actions. |

A Transmitter MUST NOT deliver an event outside its default class unless the disclosure policy
for that Receiver (§4.11.4) permits it, and SHOULD deliver every `relying`-class event to every
Receiver it knows to be relying on the affected mandate. Within a class, a Transmitter SHOULD
deliver events only for subjects the Receiver has a stake in, using SSF stream subject
management, rather than every mandate the Transmitter knows about.

Delivery of event types to a stream is controlled through the SSF stream configuration
(`events_requested` / `events_delivered`). A Receiver requesting an event type does not entitle
it to that type: the Transmitter MUST omit from `events_delivered` any type the Receiver is not
entitled to under this section.

#### 4.11.2. Field-Level Minimization

Even within an entitled event, the Transmitter tailors the payload per Receiver:

- **`principal`**: send a pairwise `opaque` identifier (§3) unless the Receiver needs to resolve
  the principal's identity.
- **`scope_summary`** and free-text `reason_admin` / `reason_user`: these can carry business
  terms (limits, counterparties, budgets). They MUST NOT be sent to a Receiver outside the
  `internal` class unless the disclosure policy for that Receiver permits it. Structured fields
  (`reason`, `change_class`, `violation_type`) carry the information a relying party needs to act.
- **`scope_ref` / `scope_digest`**: may be sent to any entitled Receiver; they disclose nothing
  about content (§4.11.3).
- **`order`**: `authority` may be sent to any entitled Receiver. `order_ref` MUST NOT be sent
  outside the `internal` class unless the disclosure policy for that Receiver permits it: orders,
  and the incident reports behind them, are often nonpublic, and an identifier can be enough to
  link Receivers' events to a confidential proceeding.

Events carrying a `principal` member in a resolvable format, `scope_summary`, or free-text
reasons MUST be encrypted with JWE [RFC7516] to the specific Receiver when they cross a
trust-domain boundary — a strengthening of the general SHOULD in §5.1 for exactly the payloads
that carry content.

#### 4.11.3. Referencing Scope Instead of Copying It

- **`scope_digest`** — a digest of the authoritative mandate artifact, as
  `"<alg>:<base64url digest>"` (e.g. `sha-256:...`). It MUST be computed over the complete
  artifact as issued (for a JWT-encoded mandate, its full compact serialization), not over the
  scope fields alone: scope values such as limits or action names are low-entropy and could be
  recovered from a bare digest by guessing, whereas the complete artifact contains unpredictable
  values (its identifier and signature). A Receiver that holds a mandate compares digests to
  confirm which version an event concerns; a Receiver that does not hold it learns nothing.
  Where the mandate is not a single signed artifact — for example an OAuth grant held as a
  record at the authorization server, whose granted `authorization_details` are exactly the
  low-entropy content this rule protects — the digest MUST be computed over a canonical
  serialization [RFC8785] of the authority's authoritative record that includes the mandate's
  identifier and at least 128 bits of unpredictable value bound to that record, never over the
  `authorization_details` or `scope` alone.
- **`scope_ref`** — an `https` URI from which an authorized Receiver can obtain the
  authoritative mandate. Dereferencing MUST require the Receiver to authenticate, and the
  endpoint MUST apply the same disclosure policy as the event stream. The Receiver MUST verify
  the obtained artifact (signature, and `scope_digest` when present) before relying on it, and
  SHOULD fetch only from endpoints within the Transmitter's own trust domain. A Transmitter
  SHOULD omit `scope_ref` for Receivers not entitled to the content.

#### 4.11.4. Who Decides

Disclosure is decided by the party that granted the authority, not by the Transmitter's
convenience. The issuing authority defines a disclosure policy — for each mandate, or for a class
of mandates — stating which Receivers or Receiver classes may receive which events and fields.
The policy MAY travel with the mandate itself, so that a mandate carries its own rule for who may
learn of changes to it. This profile does not define the policy's encoding; it requires only that:

- the Transmitter enforces the applicable policy at both stream level (§4.11.1) and field level
  (§4.11.2);
- in the absence of a policy, the defaults in §4.11.1 and §4.11.2 apply;
- a policy may widen disclosure beyond the defaults, but MUST NOT suppress delivery of
  `relying`-class events to Receivers relying on the affected mandate. Withholding a revocation
  or narrowing from the parties who rely on the authority defeats the purpose of this profile.

### 4.12. Externally Ordered Changes

An authority outside the issuing trust domain — a regulator, a court, a public body acting under
emergency powers — may order the issuing authority, or the operator of a system its workloads
depend on, to restrict or stop that system (§1.4). MLE defines no event for the order itself. It
signals the changes to mandates that carrying out the order produces, using the events already
defined above.

#### 4.12.1. Mapping Ordered Measures to Events

Orders are commonly framed as a graduated set of measures. The set below follows the graduated
framework of [HR9917] (proposed §2220F(b)(1)(A) and (b)(2)(A)) as a representative example; other
regimes use similar measures under other names.

| Ordered measure | MLE signal |
|---|---|
| Stop inference, or terminate access for all users | `mandate-suspended` (or `mandate-revoked`, §4.12.2) for every mandate exercised through the affected system, `cascade` from each root mandate |
| Suspend access for an account or user | `mandate-suspended` for the mandates held by that account or user and, by `cascade`, those delegated from them |
| Suspend access for a use pattern | As above, for the mandates the pattern covers. A use pattern is not a subject: the Transmitter resolves it to the mandates concerned, and signals each |
| Restrict user access; disable or restrict a capability | `mandate-rotated`, `change_class: narrowed`, where the restriction changes what a mandate authorizes |
| Throttle inference rate or compute allocation | None. A rate or capacity limit that leaves unchanged what a mandate authorizes is not a mandate change |
| Move operation to a backup system or an earlier version | None in MLE. This changes the workload, not its authority, and is signaled, if at all, by WISE. Whether mandates continue under the replacement is for the issuing authority to decide; if they do not, it signals `mandate-rotated` (`narrowed`) or `mandate-suspended` |
| Shut down | As for "stop inference" |

A Transmitter MUST NOT signal an ordered measure with a relaxing event (§5.9). Where it cannot
tell which of a Receiver's mandates a measure affects, it MUST signal the broader set.

#### 4.12.2. Suspension Rather Than Revocation

Orders may be reconsidered, appealed or overturned — [HR9917], for example, provides for a
petition for reconsideration and for judicial review, neither of which stays the order.
Revocation is terminal (§5.8), so an ordered stop signaled as a revocation cannot be undone when
the order is lifted, and every principal would have to grant its mandates again. A Transmitter
SHOULD therefore carry out an ordered stop with `mandate-suspended`, `reason: external_order`,
and SHOULD use `mandate-revoked`, `reason: external_order`, only where the order itself ends the
authority permanently or the issuing authority decides to end it. When the order is lifted, the
Transmitter concludes the suspension with `mandate-resumed` (§4.8); when it becomes final, with
`mandate-revoked` carrying the `suspension_id`.

#### 4.12.3. Processing Rules

- Every event that carries out an order MUST carry the `order` claim (§2.2). All SETs arising
  from one order SHOULD share one SET `txn` (§2.3), across MLE and WISE event types and across
  Receivers. Together, the events a Receiver receives under one `txn` tell it which of the
  mandates it relies on are affected and how.
- The `order` claim does not change how an event is processed. An ordered suspension, revocation
  or narrowing is a tightening signal and is acted on as §5.9 requires; the claim makes it
  neither more nor less authoritative. A Receiver MUST NOT treat `order` as evidence that an order
  exists, and MUST NOT accept a relaxing event more readily because it carries one.
- An order may require delivery to Receivers outside an event's default disclosure class. The
  issuing authority then widens its disclosure policy (§4.11.4) for those events; the content
  rules of §4.11.2 continue to apply.
- An order made against an operator may require it to notify parties that hold no mandate and
  rely on none, such as the end users of a hosted service. Such notification is outside this
  profile.
- Delivery evidence for events sent under an order is addressed in §5.10.

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
apply rate limiting independent of any single event's validity.

For `mandate-revoked` with `revocation_type: cascade`, a Receiver that walks descendant mandates
in response SHOULD perform this cheaply-checkable field comparison before any expensive lookup or
policy evaluation.

### 5.4. Compromise Response

This section states for MLE the behavior WISE `-04` requires of its own events; it is restated
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
prior `mandate-executed` event (e.g. an already-issued Transaction Token). The credential remains
valid for whatever lifetime it was issued with. The actual enforcement point is the *next*
`mandate-executed` request, which the issuing authority is expected to refuse once the mandate is
revoked. For OAuth-issued credentials this is the check an authorization server already performs
against the underlying grant on every token request ([RFC9396], §6). The resulting exposure window
is bounded by the *longest*-lived credential still outstanding under the mandate — with
Transactional Access Tokens, by their short lifetime [TXN-AT]. This is a real, quantifiable bound
a deployment can state, not a gap to hide; `credential_expiry` on `mandate-executed` (§4.4) lets a
Receiver compute it. A Receiver that holds a still-valid credential issued under a revoked or
suspended mandate SHOULD stop accepting it on receipt of the event rather than wait for expiry.

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
  Receiver accepts authority only on verifying the authoritative mandate itself (§4.5, §4.11.3,
  §5.6). `mandate-resumed` restores authority the Receiver already held rather than adding new
  authority, so §4.8 sets a graduated rule: confirmation is REQUIRED after a reported
  compromise and RECOMMENDED otherwise. An attacker who controls a Transmitter, or a misconfigured one, can then at worst cause
  refusals, not unauthorized actions.

This mirrors the observation that, for any signal able to relax a prior restriction, a spurious
relaxation suppresses protection silently and so warrants more assurance than a spurious
tightening.

### 5.10. Evidence of Delivery

An authority that ordered a change (§4.12) may require the party it ordered to confirm that the
order was carried out, and may verify that confirmation afterwards; [HR9917] would require both.
A Receiver may later need to show when it learned that a mandate had been stopped. Interference
with a shutdown instruction can itself be the incident at issue, and showing it requires showing
that the instruction was delivered.

MLE events are SETs signed by the Transmitter, and SSF delivery already produces an
acknowledgement: the Receiver's success response in push delivery [RFC8935], or its
acknowledgement of the SET's `jti` in poll delivery [RFC8936]. For each SET sent to carry out an
order, a Transmitter SHOULD retain the SET as sent, the Receiver it was addressed to, and whether
and when its delivery was acknowledged, and SHOULD retry delivery of an unacknowledged SET
according to the delivery method in use. A Receiver SHOULD retain each such SET with the time it
applied it. Retained records can be made tamper-evident by registering them with a transparency
service; this profile does not require one.

This is evidence that a change was signaled and received, not that it was enforced: an
acknowledgement shows that a Receiver received a suspension, not that it stopped accepting the
mandate. `mandate-violation-detected` with `violation_type: ended_mandate_use` (§4.9) reports the
contrary case where it is observed. Showing that authority actually ended across a delegation
graph is the subject of revocation-closure work [WATTS-CLOSURE], which this profile does not
define.

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

**Content minimization:** the disclosure classes and field-level rules of §4.11 are this profile's
primary privacy control. In particular, mandates often encode commercial terms (spending limits,
counterparties, negotiation scope). Those terms belong in the authoritative mandate, reachable
through `scope_ref` by entitled Receivers, not in event payloads. A Transmitter that copies them
into `scope_summary` or free-text reasons for every Receiver turns the event stream into a feed of
the principal's business activity.

**Activity patterns:** even with minimized payloads, the timing and frequency of events — above
all `mandate-executed` — reveal what a workload and its principal are doing. Restricting those
events to the `internal` class (§4.11.1) is the main mitigation.

**Retention:** event payloads containing `principal` and `scope_summary` SHOULD be retained only
as long as needed for the stated audit/enforcement purpose, consistent with purpose limitation.
This profile does not define retention periods; deployments should state their own. A legal
obligation to preserve records, such as one accompanying an order (§4.12, §5.10), may require
longer retention; records so kept are for that obligation only.

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
Specification 1.0 - draft 04", OpenID Foundation Shared Signals Working Group, November 2026,
<https://openid.github.io/ssf-wise-profile/events-rework/>.

[TXN-TOKENS] Tulshibagwale, A., Fletcher, G., and P. Kasselman, "Transaction Tokens",
draft-ietf-oauth-transaction-tokens-11 (work in progress), July 2026,
<https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/>.

[RFC8785] Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)",
RFC 8785, June 2020, <https://www.rfc-editor.org/rfc/rfc8785>.

### 7.2. Informative References

[RFC7009] Lodderstedt, T., Ed., Dronia, S., and M. Scurtescu, "OAuth 2.0 Token Revocation",
RFC 7009, August 2013, <https://www.rfc-editor.org/rfc/rfc7009>.

[RFC8693] Jones, M., Nadalin, A., Campbell, B., Ed., Bradley, J., and C. Mortimore, "OAuth 2.0
Token Exchange", RFC 8693, January 2020, <https://www.rfc-editor.org/rfc/rfc8693>.

[RFC8935] Backman, A., Ed., Jones, M., Ed., Scurtescu, M., Ansari, M., and A. Nadalin,
"Push-Based Security Event Token (SET) Delivery Using HTTP", RFC 8935, November 2020,
<https://www.rfc-editor.org/rfc/rfc8935>.

[RFC8936] Backman, A., Ed., Jones, M., Ed., Scurtescu, M., Ansari, M., and A. Nadalin,
"Poll-Based Security Event Token (SET) Delivery Using HTTP", RFC 8936, November 2020,
<https://www.rfc-editor.org/rfc/rfc8936>.

[HR9917] U.S. House of Representatives, "AI Kill Switch Act", H.R. 9917, 119th Congress,
introduced 23 July 2026 (pending; not enacted),
<https://www.congress.gov/bill/119th-congress/house-bill/9917/text>.

[RFC9396] Lodderstedt, T., Richer, J., and B. Campbell, "OAuth 2.0 Rich Authorization
Requests", RFC 9396, May 2023, <https://www.rfc-editor.org/rfc/rfc9396>.

[GRANT-MGMT] Lodderstedt, T., Low, S., and D. Postnikov, "Grant Management for OAuth 2.0",
OpenID Foundation FAPI Working Group, <https://openid.net/specs/oauth-v2-grant-management.html>.

[TXN-AT] Tulshibagwale, A., "Transactional Access Tokens",
draft-tulshi-oauth-transactional-access-tokens-01 (work in progress), November 2026,
<https://datatracker.ietf.org/doc/draft-tulshi-oauth-transactional-access-tokens/>.

[STATUS-LIST] Looker, T., Bastian, P., and C. Bormann, "Token Status List (TSL)",
draft-ietf-oauth-status-list (work in progress),
<https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/>.

[CHEN-REVOCATION] Chen, M. and L. Su, "OAuth 2.0 Agent Authorization Explicit Revocation",
draft-chen-oauth-agent-revocation (work in progress).

[WATTS-CLOSURE] Watts, "Revocation Closure and Authority Epochs for Agent Delegation",
draft-watts-oauth-agent-revocation-closure (work in progress).

[YOSSIF-MANDATE] Yossif, M. K., "Problem Statement: Verifiable Human Mandates for Autonomous
Agent Actions", draft-yossif-agent-mandate-problem (work in progress).

[AP2] "Agent Payments Protocol (AP2)", <https://ap2-protocol.org/>.

[NANDAKUMAR-REVOCATION] Nandakumar, S. and C. Jennings, "Security Events for Revocation of Agent
Delegations", draft-nandakumar-oauth-delegation-revocation-00 (work in progress), November 2026,
<https://datatracker.ietf.org/doc/draft-nandakumar-oauth-delegation-revocation/>.

[PACE-AUTHZ] Nandakumar, S. and C. Jennings, "PACE Authorization: Delegation and Action
Approval", draft-nandakumar-agentproto-pace-authz-00 (work in progress), November 2026,
<https://datatracker.ietf.org/doc/draft-nandakumar-agentproto-pace-authz/>.

[RISC] Scurtescu, M., et al., "OpenID RISC Profile Specification 1.0", 2025,
<https://openid.net/specs/openid-risc-1_0-final.html>.

[WIMSE-ARCH] Salowey, J., Rosomakho, Y., and H. Tschofenig, "Workload Identity in a Multi
System Environment (WIMSE) Architecture", 2026,
<https://www.ietf.org/archive/id/draft-ietf-wimse-arch-07.html>.

## 8. Open Questions for the Working Group

- **Suspension status endpoint** — §4.8 requires a Receiver to confirm status before resuming
  after a reported compromise, and suggests the `scope_ref` endpoint report suspensions. Should
  this profile define that status response, leave it to the mandate format, or point to an
  existing pull mechanism such as Token Status List [STATUS-LIST], whose `SUSPENDED` status
  already matches this case?
- **OAuth grants as the default mandate** — §1.4 maps `mandate_id` to Grant Management's
  `grant_id` and the enforcement point to RAR's token-request check. Should MLE include a short
  OAuth binding (grant → mandate, token exchange → child mandate, Transactional Access Token →
  `mandate-executed`), or leave that to a separate profile? Grant Management's query API is
  available only to the client that holds the grant, so it cannot serve as `scope_ref` for a
  resource server as it stands.
- **Namespace and registry** — WISE `-04` establishes a "WISE Event Types" IANA registry
  (Specification Required) under its own base URI. Registering MLE events there would make MLE a
  WISE extension, which this profile is deliberately not (§1.2). The working assumption is a
  separate "MLE Event Types" registry under the `/secevent/mandate/` base URI, using the same
  registration policy and expert criteria as WISE's. Is that the right call, or is a shared
  registry with distinct prefixes preferable?
- **Token-chain subjects** — [NANDAKUMAR-REVOCATION] identifies a delegated token by a
  `delegation` subject format (`iss`, `jti`). Should MLE accept that format as the Simple Subject
  of `mandate-revoked` when a mandate is carried as a single token, so that one revocation
  can be expressed consistently in both vocabularies?
- **Failed rotation** — WISE `-04` gives `credential-rotated` a REQUIRED `status`
  (`succeeded`/`failed`). Should `mandate-rotated` report a failed renewal the same way, or is a
  failed renewal simply the absence of a successor before `expiry`?
- **`mandate-rotated` naming** — with `change_class`, this event now covers any replacement of a
  mandate by a successor, including narrowing and widening, not only routine renewal. Would
  `mandate-superseded` be a clearer name?
- **Disclosure policy encoding** — §4.11.4 requires an issuer-defined disclosure policy but leaves
  its encoding out of scope. Is a common encoding worth standardizing (for example as a claim in
  the mandate token), or should it remain deployment-specific?
- **Relationship to Transaction Tokens and Transactional Access Tokens** — `mandate-executed`'s
  `credential_type` values `txn_token` and `txn_at` are intended as concrete bridges to
  [TXN-TOKENS] and [TXN-AT]. Feedback on whether this is the right level of coupling, or whether
  it should be looser, would be useful.
- **An event for the order itself** — §4.12 signals an order only through the per-mandate events
  it produces, tied by `order` and a shared `txn`. Is an event whose subject is the order needed
  (for example, so that Receivers holding no affected mandate still learn of it)? Its subject
  would be neither a workload nor a mandate, so it may belong in a profile shared with WISE
  rather than in MLE.
- **`order` as a shared claim** — WISE events such as `workload-disabled` and
  `credential-revoked` can also carry out orders. Should `order` be defined once, for both
  profiles, rather than in MLE alone?
- **Use patterns as subjects** — orders may target a "use pattern" rather than an account or
  user (§4.12.1). This profile resolves the pattern to mandates. Is a subject format for a
  pattern worth defining, or is resolution by the Transmitter the right boundary?
- **Reporting `ended_mandate_use` upstream** — Receivers are usually the first to see a stopped
  mandate being used (§4.9), but SSF streams flow toward them. Should this profile recommend a
  reverse stream, from relying party to issuing authority, for this one event?
- **Mandates across a model change** — when a workload is moved to a backup system or an earlier
  model version (§4.12.1), should its mandates be presumed to continue, or should the authority
  be required to state it?

## Document History

**28 November 2026 — externally ordered changes**

- §1.4: new paragraph on emergency orders from public authorities, citing the proposed U.S. AI
  Kill Switch Act [HR9917] as an example; MLE stays jurisdiction-neutral.
- §2.2: new common optional claim `order` (`authority`, `order_ref`) — identifies an order, never
  its content.
- `mandate-revoked` and `mandate-suspended`: new `reason` value `external_order`. §4.8: resumption
  after an ordered suspension requires status confirmation, as after a reported compromise.
- `mandate-violation-detected`: new `violation_type` `ended_mandate_use`.
- New §4.12, Externally Ordered Changes: mapping of graduated measures (stop, terminate, suspend
  by account/user/use pattern, restrict, throttle, roll back, shut down) to existing events — no
  new event types; ordered stops SHOULD be suspensions, not revocations, since orders can be
  overturned; processing rules.
- §4.11.2: `order_ref` restricted to the `internal` class by default. §4.10: CRUD table row.
- New §5.10, Evidence of Delivery: retention of SETs and SSF delivery acknowledgements
  [RFC8935]/[RFC8936] for events sent under an order. §6: legal preservation and retention.
- Open Questions: an event for the order itself; `order` shared with WISE; use-pattern subjects;
  reporting `ended_mandate_use` upstream; mandates across a model change.

**21 November 2026 — follow-ups from WISE Draft-05 issues (#32/SSF #359, #40, #41)**

- §2.2 `effective_at`: MUST NOT be later than the SET's `iat` (SETs report what has happened;
  a future-dated change could not be cancelled, and revocation is terminal). An earlier value is
  allowed and means "effective since". A planned end of authority is a `mandate-rotated`
  (`narrowed`) with an earlier `expiry`; other planned changes are held by the Transmitter.
- `mandate-rotated`: new OPTIONAL `expiry` for the successor, REQUIRED when the only change is
  an earlier expiry.
- `mandate-revoked`: the scheduled-revocation note is replaced accordingly.
- `mandate-suspended`: the issuing authority SHOULD conclude every suspension; a Receiver MAY
  re-check a long-open suspension but MUST NOT lift it itself. `suspension_id` MUST NOT be an
  internal ticket or case reference; such pointers go in `reason_admin` or behind `scope_ref`.

**21 November 2026 — aligned to WISE `-04`**

- §1.2 boundary rewritten for WISE `-04`: `workload-degraded`/`workload-restored` are replaced by
  `workload-trust-level-change` (`full`/`reduced`/`restricted`/`minimal`); added the boundary with
  WISE's consolidated `policy-changed`.
- WISE version references in §1.2, §2.1, §2.3, §5.4 and §8 moved to `-04`; [WISE] reference
  updated.
- §1.4: added [NANDAKUMAR-REVOCATION] (`delegation-revoked` SET) and [PACE-AUTHZ].
- Open Questions: token-chain subjects; failed rotation.
- The rules MLE mirrors (`event_timestamp` REQUIRED, `effective_at`, shared `txn`,
  Compromise Response reaching profiling specifications, "WISE Event Types" registry under
  Specification Required) are unchanged in `-04`.

**19 November 2026 — landscape alignment (OAuth, RAR, Transactional Access Tokens)**

- New §1.4, Relationship to Other Specifications: CAEP/RISC/WISE; OAuth grants, RAR and Grant
  Management; Transaction Tokens and Transactional Access Tokens; Token Exchange; revocation and
  status mechanisms (RFC 7009, Token Status List, agent revocation and closure proposals);
  mandate formats (AP2, mandate problem statement). Notational Conventions renumbered §1.5.
- §2.3: the SET `txn` is distinguished from every OAuth-token `txn`, including the per-audience
  `txn` of Transactional Access Tokens.
- `mandate-executed`: new `credential_type` values `txn_at` and `access_token`; per-audience
  `credential_id` rule; new OPTIONAL `credential_expiry`.
- `mandate-rotated`: `change_class` is computed by the issuing authority under the mandate
  format's own comparison rules; when narrowing cannot be established, `expanded`.
- §4.11.3: `scope_digest` rule for mandates that are records rather than signed artifacts.
- §5.5 and §4.6 Notes: exposure window corrected to the longest-lived *outstanding* credential
  (was "shortest-lived credential type"); RAR token-request check named as the enforcement point.
- Open Questions: status endpoint now points to Token Status List as a candidate; new question
  on an OAuth binding.

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

- New §4.9 (now §4.11): per-event default disclosure classes (`internal` / `relying`) enforced through SSF
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
