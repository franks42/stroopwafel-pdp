# Changelog

All notable changes to stroopwafel-pdp. Each entry reflects committed work.

## 0.3.0 — 2026-11-24

### Security

- **stroopwafel 0.12.0 → 0.16.1.** 0.12.0 has two fail-opens fixed since:
  - an arity bypass (fixed in stroopwafel 0.13.0): a pattern of a
    different length still matched, letting checks, rule bodies and
    allow policies through;
  - origin hiding (fixed in 0.14.0, completed in 0.14.1): a block
    appended to a token could hide authorizer facts from reject checks
    and deny policies, so a revoked token became valid. See stroopwafel's
    `docs/security-advisory-2026-11-23-origin-hiding.md`.

  0.14.2 adds semi-naive evaluation (about 50× faster). 0.15.0 makes no
  policies deny instead of allow. 0.16.0 denies when a predicate is used
  with different lengths (a reject check or deny policy with a length
  typo used to never fire); 0.16.1 only counts keyword predicates, so the
  assertion facts (led by the signer's key id) aren't flagged.

### Breaking

- **`decide` throws on unknown options** (`pdp.core/decide` and
  `pdp.spki.core/decide`), with `:stroopwafel/error :unknown-keys`. A typo
  such as `:check` used to drop the checks silently.
- **No policies denies** (from stroopwafel 0.15.0): `decide` without
  `:policies` returns `{:allowed? false :warnings [{:type :no-policies}]}`;
  it used to allow whatever passed the checks. To keep that, pass
  `:policies [{:kind :allow :query []}]`.
- **Constrained capabilities derive `:can-constrained`**, not a 5-term
  `:can`: `:tmpl/capability-constrained` now has the head
  `[:can-constrained ?subject ?action ?resource ?constraints]`. With both
  `:can` lengths in one authorizer, stroopwafel 0.16's arity check would
  deny every decision. Rules and policies that matched the 5-term `:can`
  must use `:can-constrained`.
- **Arity mismatches deny** (from stroopwafel 0.16.0): a policy set, rule
  or check that uses a predicate with different lengths gets
  `{:allowed? false :error {:type :arity-mismatch …}}`.

### Added

- `decide` passes the engine's `:warnings` through, e.g.
  `{:type :no-policies}`.

### Changed

- **signet 0.3.1 → 0.10.0**, the latest on Clojars: 0.3.1 was never
  published, so the default `:test` alias and downstream consumers could
  not resolve it. The tests pass against 0.10.0 as published.

## Unreleased changes included in 0.3.0 (2026-04-11 – 2026-10-25)

- **`decide` passes `:limits` to the engine and returns its `:error`**
  (stroopwafel 0.12.0): a deny caused by a fixpoint limit no longer looks
  like a policy deny.
- `build.clj` (`clojure -T:build install`, and `deploy` to Clojars since
  0.3.0); `deps.edn` resolves signet and
  stroopwafel as `:mvn/version`, with a `:dev` alias overriding both with
  `:local/root` checkouts.

## 0.2.0 — 2026-04-11

The SPKI/SDSI assertion pipeline (`stroopwafel.pdp.spki.*`): signed
assertion blocks, the pre-filter (signature, validity, trust closure,
per-assertion trust, revocation), template rules for `:capability`,
`:name-binding`, `:delegation` and `:revocation`, and `decide`. Builds on
the bridge between signet (crypto) and stroopwafel (logic) scaffolded on
2026-04-10.
