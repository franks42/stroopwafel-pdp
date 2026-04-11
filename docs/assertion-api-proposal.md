# stroopwafel-pdp: SPKI/SDSI Assertion Model — API Proposal

**Status:** design, pre-implementation
**Branch:** `spki-sdsi`
**Date:** 2026-04-11
**Author:** Frank Siebenlist (concept) + Claude Opus 4.6 (documentation)
**Based on:** `stroopwafel/docs/generic-assertion-schema.md` and its
Claude/Gemini/GPT reviews

---

## Goal

Give `stroopwafel-pdp` a first-class entry point for verified assertions —
signed statements with mandatory sayer, timestamp, not-before, not-after,
assertion-id, and queryable revocation. The existing `add-chain` path
(Biscuit-shaped) stays unchanged; this is additive.

**Leverages:** `signet` (sign-edn, key/kid), `stroopwafel.core` (engine), the
existing PDP context shape. All of the refactoring payoff from the v0.8.0
migration lands here: signet does crypto, stroopwafel.core stays pure,
stroopwafel-pdp gains the new pre-filter pipeline as its value-add.

## Scope / non-goals

- **In scope:** SPKI/SDSI assertion model, pre-filter pipeline, trust closure,
  revocation handling, standard templates, compatibility with existing
  chain-based flows.
- **Not in scope (deferred):** quorum/threshold signing schemes, content-hash
  assertion IDs, streaming/updates, strict schema enforcement, CBOR encoding.

## Isolation strategy

All new code lives in a **separate namespace tree** — no mixing with the
existing `stroopwafel.pdp.{core,trust,replay}` namespaces. This keeps the
existing Biscuit-shaped path untouched, makes the new code trivially
deletable if the approach doesn't pan out, and lets the two models evolve
independently.

```
src/stroopwafel/pdp/
  core.clj          ← existing, untouched (chain-shaped PDP)
  trust.clj         ← existing, untouched
  replay.clj        ← existing, untouched
  spki/             ← NEW — parallel tree for the assertion model
    core.clj        ← context + add-assertions + decide
    assertion.clj   ← sign-block, verify-block, ->assertion constructor
    templates.clj   ← standard templates
    trust.clj       ← trust closure + delegation
    revocation.clj  ← in-band + external revocation collection
```

Development happens on the `spki-sdsi` branch. If it works, merge to main
as a v0.2.0 feature. If it doesn't, delete the branch and nothing is lost.

## 1. Data model

### On the wire: an **assertion block** is a signed envelope

One block = one sayer, one timestamp, one validity window, **N assertions**.
Signed once via `signet.sign/sign-edn`. All assertions in the block share the
sayer and temporal metadata — they inherit from the envelope header.

```clojure
;; A signed assertion block (produced by spki.assertion/sign-block,
;; verified by signet.sign/verify-edn)
{:type      :signet/signed
 :envelope  {:message    {:not-before <epoch-ms>         ; shared by all assertions
                          :not-after  <epoch-ms>         ; shared by all assertions
                          :assertions [{:id         <uuidv7>
                                        :type       :capability
                                        :statement  ["alice" :read "/data"]}
                                       {:id         <uuidv7>
                                        :type       :name-binding
                                        :statement  ["alice" "ops-team"]}]}
             :signer     <kid-urn>         ; sayer, signet fills
             :request-id <uuidv7>          ; signing event id, signet fills
             :expires    <epoch-ms>}       ; optional whole-block hard expiry
 :signature <bytes>}
```

Shared metadata (sayer, signing timestamp, validity window) lives on the
envelope. Per-assertion data (id, type, statement) lives inside. At
pre-filter time each assertion is **expanded** into a logical 7-tuple
(sayer + ts + nb + na + type + id + statement) so queries that care
about sayer or timestamps can join on them.

**Rationale:** shared metadata on the envelope is the compact physical
encoding all three reviewers converged on. No per-assertion signatures, no
redundancy, drops straight into the signet primitives we already have.

### Multi-assertion inheritance — the one subtlety

Every assertion in a block inherits:

- **sayer** (from envelope `:signer`) — non-negotiable; all assertions in a
  block have the same attribution
- **ts** (derived from envelope `:request-id` UUIDv7 timestamp) — the
  signing moment
- **not-before** and **not-after** (from envelope `:message`) — the
  validity window

If you need assertions with different sayers, use multiple blocks. If you
need assertions with different validity windows, use multiple blocks. A
block is the unit of "these facts all come from the same party, asserted
at the same time, valid for the same window." That's the whole point of
block-level signing — you pay one signature per cohort, not per fact.

### In the Datalog store: flat inlined tuples

After pre-filter, each assertion becomes one fact in the authority block:

```clojure
;; Position: 0     1   2          3          4              5    6+
;;          sayer  ts  not-before not-after  assertion-type id   <statement...>

[alice-kid 1743000000000 1743000000000 1743086400000
 :capability #uuid "cap-1" "alice" :read "/data"]
```

The statement is **inlined** (flattened from position 6 onward), not
nested. `:capability` at position 4 discriminates the type; positions
6+ are type-specific arguments. No redundant `[:capability ...]` wrapper
inside the tuple.

## 2. Context state

The SPKI context is a separate record from the existing chain-shaped one:

```clojure
(ns stroopwafel.pdp.spki.core ...)

(defn context
  [& {:keys [clock-skew-ms current-time-fn]
      :or   {clock-skew-ms   5000                        ; Gemini's recommendation
             current-time-fn #(System/currentTimeMillis)}}]
  {:type            :stroopwafel.pdp.spki/context
   :assertions      []         ; raw signed blocks before pre-filter
   :facts           []         ; injected service-local context (unsigned)
   :rules           []         ; user rules
   :checks          []         ; user checks
   :trust-roots     #{}        ; primordial trusted sayer kids
   :templates       []         ; derivation templates
   :revocation-src  nil        ; optional fn: () → {:ids :keys :subjects}
   :clock-skew-ms   clock-skew-ms
   :current-time-fn current-time-fn
   :errors          []})
```

The three-layer separation from the schema doc is visible in the context:

- `:assertions` — **data** (signed, pre-filtered, becomes Datalog facts)
- `:templates` + `:rules` — **code** (derivation logic, not signed, not delegatable)
- `:facts` — **injected context** (service-local, implicitly trusted)

## 3. API functions

### `stroopwafel.pdp.spki.core`

```clojure
(defn context ...)
;; build an empty SPKI context

(defn add-assertions [ctx signed-block])
;; Add a signed assertion block. Verification is lazy (at decide time),
;; so the context just accumulates blocks.

(defn add-assertion [ctx signed-block-with-one-assertion])
;; Convenience: single-assertion shortcut.

(defn add-trust-roots [ctx trust-roots])
;; Register primordial trust roots. Accepts a kid URN string, a set of
;; strings, or a map {kid → {:for-types #{...} :scoped-to {...}}}.
;; Primordial trust is set at service startup, not inside tokens.
;; Delegated trust is a :delegation assertion inside a block.

(defn with-templates [ctx templates])
;; Register derivation templates. Datalog rules that unpack assertion
;; tuples into clean named predicates. Library-supplied templates cover
;; :capability, :name-binding, :revocation, :delegation; user templates
;; can extend for custom assertion types.

(defn with-revocation-source [ctx f])
;; Register a function returning {:ids #{...} :keys #{...} :subjects #{...}}.
;; Used for out-of-band revocation (live feeds). In-band :revocation
;; assertions inside blocks are always collected regardless.

(defn add-facts [ctx facts])          ; injected service-local facts
(defn add-rules [ctx rules])          ; user-provided rules
(defn add-checks [ctx checks])        ; user-provided checks

(defn decide [ctx & {:keys [policies rules checks explain?]}])
;; Runs the full pre-filter pipeline, then stroopwafel.core/evaluate.
;; Returns {:allowed? boolean} or {:allowed? false :errors [...]}.
;; With :explain? true, includes the reduction trace.
```

### `stroopwafel.pdp.spki.assertion`

```clojure
(defn assertion
  "Construct an individual assertion map.
   (assertion :capability [\"alice\" :read \"/data\"])
   (assertion :capability #uuid \"cap-1\" [\"alice\" :read \"/data\"])"
  ([type statement] ...)
  ([type id statement] ...))

(defn sign-block
  "Sign a block of assertions with a sayer keypair.

   Options:
     :not-before  — epoch-ms (default: signing timestamp)
     :not-after   — epoch-ms (REQUIRED — see §5 below)
     :assertions  — vector of assertion maps from (assertion ...)

   Returns a signet signed envelope."
  [keypair {:keys [not-before not-after assertions]}] ...)

(defn verify-block
  "Verify a signed block's envelope signature. Used internally by the
   pre-filter; exposed for debugging. Does NOT check temporal validity,
   revocation, or trust — that's the pre-filter's job."
  [signed-block] ...)
```

## 4. Pre-filter pipeline (inside `decide`)

The heart of the thing. Called once per `decide`, before any Datalog runs.

```clojure
(defn- pre-filter-assertions
  "Four-check pre-filter: signature, temporal, revocation, trust.
   Assertions that fail any check are dropped (tracked in :rejected
   for :explain). Survivors become Datalog facts."
  [ctx]
  (let [now       ((:current-time-fn ctx))
        skew      (:clock-skew-ms ctx)
        ;; Pass 1: verify signatures on each block
        verified  (keep (fn [signed-block]
                          (let [r (signet.sign/verify-edn signed-block)]
                            (when (:valid? r) r)))
                        (:assertions ctx))
        ;; Pass 2: collect revocation set from :revocation assertions
        ;;         in verified blocks + external source if any
        rev-set   (collect-revocations verified (:revocation-src ctx))
        ;; Pass 3: resolve trust closure (primordial + delegation)
        trusted   (resolve-trust-closure (:trust-roots ctx) verified now skew)
        ;; Pass 4: temporal + revocation + trust filter
        survivors (mapcat
                    (fn [v]
                      (let [sayer (:signer v)
                            msg   (:message v)
                            nb    (:not-before msg)
                            na    (:not-after msg)
                            block-ts (:timestamp v)]
                        (for [a (:assertions msg)
                              :when (temporally-valid? nb na now skew)
                              :when (not (revoked? rev-set (:id a) sayer a))
                              :when (trusted-for? trusted sayer (:type a))]
                          (into [sayer block-ts nb na (:type a) (:id a)]
                                (:statement a)))))
                    verified)]
    {:facts survivors
     :rejected ...}))
```

The survivors go into the Datalog store as facts (alongside injected
`:facts`, templates as rules, and any chain-contributed facts if used in
hybrid mode). Templates derive clean predicates; the policy query joins
on those.

## 5. Temporal defaults — the hard design question

**`:not-before` default:** signing timestamp, derived from the envelope's
UUIDv7 `:request-id` (no extra work — signet already embeds this). Obvious,
no debate.

**`:not-after` default:** genuinely difficult. Options under discussion:

1. **No default, hard-require explicit `:not-after`.** Matches the schema
   doc's stance. Safest; no eternal assertions by accident. Forces every
   issuer to make a deliberate choice.
2. **Short default (e.g., 1 hour) with warning.** Like JWT access tokens.
   Silently breaks legitimate longer-lived cases.
3. **Configurable default per context.** E.g., `(sign-block kp block {:default-ttl (hours 24)})`.
   Still a hidden default, just moved.
4. **Type-specific defaults.** `:revocation` defaults to "effectively
   forever"; other types require explicit `:not-after`. Subtle but
   defensible: revocations have inverted expiry semantics.

Per-type nuance for `:revocation`: a revocation assertion that expires
stops blocking the revoked item once it expires. That's almost never
what you want — revocations are intended to be near-permanent. So for
revocations, a large default (signing-ts + ~100 years, or a sentinel) is
both safer and more ergonomic than requiring every revocation issuer to
pick a giant number.

**Proposal (subject to confirmation):** combine #1 and type-specific #4.

- For `:capability`, `:name-binding`, `:delegation`, and all custom
  types: **`:not-after` is required.** `sign-block` throws if omitted.
  The error message should suggest a concrete value and a rationale
  (e.g., "8 hours for interactive sessions, 24 hours for background
  agents, 30 days for service-to-service trust").
- For `:revocation`: **`:not-after` defaults to signing-ts + 100 years**
  if omitted. Effectively permanent, but still finite (no Long/MAX_VALUE
  sentinel — revocations *will* eventually age out, just not on any
  timescale you'll notice).

This keeps the schema doc's "no eternal assertions" discipline for the
types where eternity is dangerous, while handling the one type where
near-eternity is the right default. *Open question: does the community
want this type-specific behavior, or hard-require for everything?*

**Alternative worth considering:** a convenience `sign-block-with-ttl`
that takes a `:ttl` in seconds and computes `:not-after = signing-ts + ttl`.
Both values are visible at the call site — no hidden magic — and the
ergonomics are good:

```clojure
(spki/sign-block-with-ttl root-kp
  {:ttl        (* 24 60 60)         ; 24 hours, explicit at call site
   :assertions [...]})
```

This doesn't replace the mandatory-not-after rule for `sign-block`, but
gives a pleasant front door.

## 6. Standard templates

Shipped as `stroopwafel.pdp.spki.templates/standard`:

```clojure
(def standard
  '[;; :capability → [:can ?subject ?action ?resource]
    {:id   :tmpl/capability
     :head [:can ?subject ?action ?resource]
     :body [[?_ ?_ ?_ ?_ :capability ?_ ?subject ?action ?resource]]}

    ;; :capability with constraints map
    {:id   :tmpl/capability-constrained
     :head [:can ?subject ?action ?resource ?constraints]
     :body [[?_ ?_ ?_ ?_ :capability ?_ ?subject ?action ?resource ?constraints]]}

    ;; :name-binding → [:named ?key ?name]
    {:id   :tmpl/name-binding
     :head [:named ?key ?name]
     :body [[?_ ?_ ?_ ?_ :name-binding ?_ ?key ?name]]}

    ;; :revocation by assertion id
    {:id   :tmpl/revoked-assertion
     :head [:revoked ?id]
     :body [[?_ ?_ ?_ ?_ :revocation ?_ :assertion ?id]]}

    ;; :revocation by sayer key
    {:id   :tmpl/revoked-key
     :head [:revoked-key ?k]
     :body [[?_ ?_ ?_ ?_ :revocation ?_ :key ?k]]}

    ;; :revocation by subject
    {:id   :tmpl/revoked-subject
     :head [:revoked-subject ?s]
     :body [[?_ ?_ ?_ ?_ :revocation ?_ :subject ?s]]}

    ;; :delegation → [:delegated ?delegator ?delegate ?type ?scope]
    {:id   :tmpl/delegation
     :head [:delegated ?delegator ?delegate ?type ?scope]
     :body [[?delegator ?_ ?_ ?_ :delegation ?_ ?delegate ?type ?scope]]}])
```

Policy authors never see positional details — they write queries against
`[:can …]`, `[:named …]`, `[:delegated …]`. Raw fact matching still works
for anyone who wants it; templates are conventions, not constraints.

## 7. Revocation

Two sources, both feeding the same pre-filter:

1. **In-band:** `:revocation` assertions carried alongside capability
   assertions (in their own blocks, signed by a party trusted for the
   revocation scope).
2. **Out-of-band:** `with-revocation-source` registers an `IFn` that
   returns the live revocation set on each `decide` call. Useful for
   services that maintain a revocation feed out of the token path.

Three scopes:

- `[:revocation :assertion <id>]` — targeted
- `[:revocation :key <kid>]` — broad (all assertions ever signed by that
  sayer)
- `[:revocation :subject <name>]` — middle (all assertions about this
  subject, regardless of issuer). The incident-response sweet spot.

## 8. Delegation + trust closure

`resolve-trust-closure` computes the set of trusted sayers via fixpoint:

```
trusted := primordial trust-roots
changed := true
while changed:
  changed := false
  for block in verified-assertions where block.sayer ∈ trusted:
    for a in block.assertions where a.type = :delegation:
      delegate := a.statement[0]
      del-type := a.statement[1]
      del-scope := a.statement[2]
      ;; narrow to intersection of delegator's own trust window/scope
      effective := {:until (min block.not-after trusted[block.sayer].until)
                    :scope (intersect del-scope trusted[block.sayer].scope)
                    :for-type del-type}
      if delegate ∉ trusted OR effective is tighter:
        trusted[delegate] := effective
        changed := true
return trusted
```

**Attenuation guarantee:** a delegate can never be trusted for a wider
scope or longer window than their delegator — enforced by the
intersection at each step.

## 9. Injected state

Stays in `:facts`. Unsigned, implicitly trusted, ephemeral. Kept strictly
separate from assertion-derived facts via different origin tags. This
preserves the three-layer boundary: a compromised token issuer can't
override injected state, and a malicious injection can't masquerade as a
signed assertion.

Scope-isolation mechanism: pre-filter survivors get origin `:spki/assertion`;
injected `:facts` get origin `:spki/injected`. Templates only match
`:spki/assertion`-origin facts, enforcing that only signed data can flow
through derivation logic.

## 10. Coexistence with `add-chain`

The two paths are entirely separate namespace trees (`stroopwafel.pdp.core`
vs `stroopwafel.pdp.spki.core`). Typical deployment picks one. Hybrid
deployments would require explicit plumbing — mixing chain-contributed
facts and assertion-contributed facts into the same Datalog evaluation.
This is **not** a Phase 1 concern. If hybrid turns out to be important,
it's a follow-up design.

For now: `stroopwafel.pdp.core` stays the Biscuit-shaped PDP;
`stroopwafel.pdp.spki.core` is the SPKI/SDSI PDP; callers pick one.

## 11. Open questions needing a decision

1. **Not-after default** (the big one): hard-require for all types, or
   type-specific with near-eternity default for `:revocation`? See §5.
   *Proposal: type-specific.*

2. **Assertion-id format:** UUIDv7 (simple, time-ordered, matches signet's
   `:request-id`) or content hash (deterministic, dedup-friendly)?
   *Proposal: UUIDv7 now; content-hash later if dedup turns up as a real
   need.*

3. **Revocation source return shape:**
   `{:ids #{…} :keys #{…} :subjects #{…}}` (three sets) or a single
   tagged set `#{[:id x] [:key y] [:subject z]}`?
   *Proposal: three sets, clearer intent and faster lookups.*

4. **Templates registry scope:** per-context (explicit `with-templates`)
   or global default? *Proposal: per-context. One extra line at the call
   site beats one hidden default for decades.*

5. **Clock skew symmetry:** symmetric by default, or asymmetric (lenient
   not-before, strict not-after)? *Proposal: symmetric by default. Expose
   asymmetric params if someone needs them later.*

6. **Pre-filter rejection surfacing:** invalid assertions as `:errors`
   (short-circuit decide) or silent-with-explain (decide proceeds, drops
   visible in `:explain`)? *Proposal: silent + `:explain`. An invalid
   assertion shouldn't deny a request that would otherwise be allowed by
   other valid assertions. That's the SPKI/SDSI compositionality win
   over Biscuit chains.*

7. **Primordial trust-root overlap with delegation:** if root A delegates
   to B, and B is already a primordial trust-root, what's B's effective
   scope? *Proposal: widen — take the union of primordial and delegated
   scopes (max window, max scope). Primordial is a "floor" that
   delegation can only raise, never lower.*

8. **Block-signing key vs assertion subject constraint:** should the
   sayer be constrained at all? (Can a random key sign a block asserting
   "alice is in ops-team"?) *Proposal: no constraint. Trust-closure is
   the only gatekeeper; sayer is just an identity. This is the SPKI
   model — anyone can say anything, the receiver decides who to believe.*

## 12. Phased implementation plan

**Phase 1 — schema + signing** (~1 day)
- `stroopwafel.pdp.spki.assertion`: `assertion`, `sign-block`, `verify-block`
- Tests: round-trip, tamper detection, temporal round-trip,
  multi-assertion inheritance

**Phase 2 — context + pre-filter** (~2 days)
- `stroopwafel.pdp.spki.core`: new `context`, `add-assertions`,
  `add-trust-roots`, `with-templates`, `with-revocation-source`,
  `add-facts`, `add-rules`, `decide`
- `pre-filter-assertions` through pass 4 (no delegation yet)
- Tests: sig/temporal/revocation filters, happy paths

**Phase 3 — trust closure + delegation** (~2 days)
- `stroopwafel.pdp.spki.trust`: `resolve-trust-closure`, `trusted-for?`
- Delegation scope/validity narrowing
- Tests: direct trust, 1-hop delegation, 2-hop delegation, over-wide
  delegation rejection, expired delegation

**Phase 4 — templates** (~1 day)
- `stroopwafel.pdp.spki.templates/standard`
- Integration: templates feed as extra rules into `decide`
- Tests: policy queries against `[:can …]`, `[:named …]`, `[:delegated …]`

**Phase 5 — revocation plumbing** (~1 day)
- `stroopwafel.pdp.spki.revocation`: `collect-revocations`,
  `with-revocation-source`
- Tests: in-band, out-of-band, combined

**Phase 6 — integration in alpaca-clj** (optional, ~1 day)
- Fourth auth mode: `:spki-sdsi`, parallel to bearer/bound/group
- Dog-food the new path against real capability scenarios

Total: ~6 days for Phases 1–5 (minimum viable), +1 day for alpaca-clj
integration.

## 13. What this doesn't cover (deferred)

- **Quorum / threshold schemes** — the schema doc mentions multi-signer
  quorum; that's a separate design pass. Accommodated in principle via
  rules over `[:approved ?req ?signer]` facts, but quorum-aware
  templates are future work.
- **Content-hash assertion IDs** — add later if dedup needed.
- **Streaming / long-lived updates** — current model is request-scoped.
  Long-lived sessions with assertion updates need a store abstraction.
- **Strict per-type schema enforcement** — templates are conventions,
  nothing stops you from putting weird arguments in a `:capability`
  statement. If strict schemas are wanted later, it's a linter pass,
  not engine work.
- **Hybrid chain + SPKI in one `decide`** — both subsystems exist, but
  mixing their facts in a single evaluation needs explicit plumbing
  that isn't in Phase 1.

---

## Design lineage

- `stroopwafel/docs/generic-assertion-schema.md` — original proposal
  (Sonnet)
- `stroopwafel/docs/generic-assertion-schema-claude-review.md` — review
  (Opus, previous session)
- `stroopwafel/docs/generic-assertion-schema-gemini-review.md` — review
- `stroopwafel/docs/generic-assertion-schema-gpt-review.md` — review
- `stroopwafel/docs/spki-sdsi-vs-biscuit.md` — conceptual comparison
- This document — concrete API sketch to actually ship the ideas
