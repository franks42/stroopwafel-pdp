(ns stroopwafel.pdp.spki.templates
  "Standard Datalog templates for SPKI/SDSI assertion types.

   Templates are rules that unpack raw assertion tuples (the 7-position
   format produced by the pre-filter — sayer/ts/not-before/not-after/
   type/id/statement) into clean named predicates, so policy authors
   never have to match positions directly.

   The `standard` var bundles the canonical set for the four built-in
   assertion types (:capability, :name-binding, :delegation,
   :revocation). Register via (spki/with-templates ctx standard).

   Users can also define their own templates following the same shape
   — they're just regular stroopwafel Datalog rules, nothing special.

   ### Note on variable naming

   Templates use unique variable names (?_sayer, ?_ts, ?_nb, ?_na,
   ?_id) for positions the head doesn't care about. Do NOT use bare
   `?_` as a wildcard here — stroopwafel's Datalog treats every
   variable-named occurrence as a real variable, so repeating `?_`
   forces unification across positions that should be independent.
   The `?_` prefix is just a Clojure-ish convention meaning 'present
   in the body but ignored by the head'.")

;; ---------------------------------------------------------------------------
;; Capability templates
;; ---------------------------------------------------------------------------

(def capability
  "3-arity :capability assertion → [:can ?subject ?action ?resource].

   Stored fact shape:
     [sayer ts not-before not-after :capability id subject action resource]"
  '{:id   :tmpl/capability
    :head [:can ?subject ?action ?resource]
    :body [[?_sayer ?_ts ?_nb ?_na :capability ?_id ?subject ?action ?resource]]})

(def capability-constrained
  "4-arity :capability assertion → [:can ?subject ?action ?resource ?constraints].

   Stored fact shape:
     [sayer ts not-before not-after :capability id subject action resource constraints]"
  '{:id   :tmpl/capability-constrained
    :head [:can ?subject ?action ?resource ?constraints]
    :body [[?_sayer ?_ts ?_nb ?_na :capability ?_id
            ?subject ?action ?resource ?constraints]]})

;; ---------------------------------------------------------------------------
;; Name-binding template
;; ---------------------------------------------------------------------------

(def name-binding
  "A :name-binding assertion → [:named ?key ?name].

   Stored fact shape:
     [sayer ts not-before not-after :name-binding id key name]

   The 'key' position is a kid URN or an intermediate name string
   (for chained name resolution); 'name' is a string identifier."
  '{:id   :tmpl/name-binding
    :head [:named ?key ?name]
    :body [[?_sayer ?_ts ?_nb ?_na :name-binding ?_id ?key ?name]]})

;; ---------------------------------------------------------------------------
;; Delegation template (exposes the delegator for audit joins)
;; ---------------------------------------------------------------------------

(def delegation
  "A :delegation assertion → [:delegated ?delegator ?delegate ?type].

   Stored fact shape:
     [sayer ts not-before not-after :delegation id delegate type]

   The sayer (position 0) IS the delegator, so it surfaces as
   ?delegator in the head — useful for audit queries like 'who
   delegated :capability rights to this key?'."
  '{:id   :tmpl/delegation
    :head [:delegated ?delegator ?delegate ?type]
    :body [[?delegator ?_ts ?_nb ?_na :delegation ?_id ?delegate ?type]]})

;; ---------------------------------------------------------------------------
;; Revocation templates (three scopes per §7 of the design doc)
;; ---------------------------------------------------------------------------

(def revoked-assertion
  "A :revocation assertion targeting an assertion-id →
   [:revoked-assertion ?target].

   Note: revocations are enforced by the pre-filter, which drops
   revoked assertions from the fact store before templates run. This
   template exposes revocations themselves for audit/debugging queries
   like 'what's been revoked recently'."
  '{:id   :tmpl/revoked-assertion
    :head [:revoked-assertion ?target]
    :body [[?_sayer ?_ts ?_nb ?_na :revocation ?_id :assertion ?target]]})

(def revoked-key
  "A :revocation assertion targeting a sayer key →
   [:revoked-key ?target]."
  '{:id   :tmpl/revoked-key
    :head [:revoked-key ?target]
    :body [[?_sayer ?_ts ?_nb ?_na :revocation ?_id :key ?target]]})

(def revoked-subject
  "A :revocation assertion targeting a subject name →
   [:revoked-subject ?target]."
  '{:id   :tmpl/revoked-subject
    :head [:revoked-subject ?target]
    :body [[?_sayer ?_ts ?_nb ?_na :revocation ?_id :subject ?target]]})

;; ---------------------------------------------------------------------------
;; Bundles
;; ---------------------------------------------------------------------------

(def standard
  "The canonical template bundle — all four assertion types, both
   capability arities, all three revocation scopes. This is the
   'batteries included' set. Users can subset or extend as needed."
  [capability
   capability-constrained
   name-binding
   delegation
   revoked-assertion
   revoked-key
   revoked-subject])

(def capabilities-only
  "Just the capability templates — for pure RBAC-ish services that
   don't use SDSI group resolution or delegation visibility."
  [capability
   capability-constrained])
