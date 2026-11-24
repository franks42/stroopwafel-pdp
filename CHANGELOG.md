# Changelog

All notable changes to stroopwafel-pdp. Each entry reflects committed work.

## 0.3.0 — 2026-11-23

### Security

- **stroopwafel 0.12.0 → 0.15.0.** 0.12.0 has two fail-opens fixed since:
  - an arity bypass (fixed in stroopwafel 0.13.0): a pattern of a
    different length still matched, letting checks, rule bodies and
    allow policies through;
  - origin hiding (fixed in 0.14.0, completed in 0.14.1): a block
    appended to a token could hide authorizer facts from reject checks
    and deny policies, so a revoked token became valid. See stroopwafel's
    `docs/security-advisory-2026-11-23-origin-hiding.md`.

  0.14.2 adds semi-naive evaluation (about 50× faster). 0.15.0 makes no
  policies deny instead of allow.

### Breaking

- **`decide` throws on unknown options** (`pdp.core/decide` and
  `pdp.spki.core/decide`), with `:stroopwafel/error :unknown-keys`. A typo
  such as `:check` used to drop the checks silently.
- **No policies denies** (from stroopwafel 0.15.0): `decide` without
  `:policies` returns `{:allowed? false :warnings [{:type :no-policies}]}`;
  it used to allow whatever passed the checks. To keep that, pass
  `:policies [{:kind :allow :query []}]`.

### Added

- `decide` passes the engine's `:warnings` through: `{:type :no-policies}`,
  and `{:type :arity-mismatch …}` when predicates are used with different
  lengths.

## Unreleased changes included in 0.3.0 (2026-04-11 – 2026-10-25)

- **`decide` passes `:limits` to the engine and returns its `:error`**
  (stroopwafel 0.12.0): a deny caused by a fixpoint limit no longer looks
  like a policy deny.
- `build.clj` (`clojure -T:build install`); `deps.edn` resolves signet and
  stroopwafel as `:mvn/version`, with a `:dev` alias overriding both with
  `:local/root` checkouts.

## 0.2.0 — 2026-04-11

The SPKI/SDSI assertion pipeline (`stroopwafel.pdp.spki.*`): signed
assertion blocks, the pre-filter (signature, validity, trust closure,
per-assertion trust, revocation), template rules for `:capability`,
`:name-binding`, `:delegation` and `:revocation`, and `decide`. Builds on
the bridge between signet (crypto) and stroopwafel (logic) scaffolded on
2026-04-10.
