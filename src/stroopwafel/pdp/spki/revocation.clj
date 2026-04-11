(ns stroopwafel.pdp.spki.revocation
  "Revocation set collection and checking for the SPKI/SDSI PDP.

   A revocation set is a plain map with three explicit scopes:

     {:ids      #{uuid ...}     — revoked assertion IDs
      :keys     #{kid ...}      — revoked sayer keys (cascades to
                                   every assertion that sayer ever
                                   signed)
      :subjects #{name ...}}    — revoked subject names (first
                                   element of an assertion's
                                   statement, by convention)

   Two sources feed into the revocation pass of the pre-filter:

   1. **In-band** — :revocation assertions carried alongside other
      assertions in signed blocks. Collected via `collect-in-band`
      after trust filtering, so only revocations from trusted sayers
      count.
   2. **Out-of-band** — a caller-supplied function returning a live
      revocation set, registered via
      `stroopwafel.pdp.spki.core/with-revocation-source`. Useful for
      services that maintain a revocation feed outside the token path.

   `collect-all` combines both. Sources compose via `combine-sources`.

   This namespace owns the revocation data model and the in-band
   collection logic; `core` orchestrates when it runs within the
   pre-filter pipeline.")

;; ---------------------------------------------------------------------------
;; Data model
;; ---------------------------------------------------------------------------

(def empty-set
  "The canonical empty revocation set. Useful as a default and for
   documentation — the shape is small but the contract is important."
  {:ids #{} :keys #{} :subjects #{}})

(defn merge-sets
  "Combine two revocation sets by unioning each scope.

   Useful when composing multiple sources, or when writing a custom
   source function that draws from multiple underlying stores."
  [a b]
  {:ids      (into (or (:ids a) #{})      (or (:ids b) #{}))
   :keys     (into (or (:keys a) #{})     (or (:keys b) #{}))
   :subjects (into (or (:subjects a) #{}) (or (:subjects b) #{}))})

;; ---------------------------------------------------------------------------
;; Source constructors
;; ---------------------------------------------------------------------------

(defn static-source
  "Return a revocation source function that always returns the same
   fixed set. Useful for tests, service startup configuration, or as
   one ingredient in `combine-sources`.

   Accepts a revocation-set map; missing scopes default to empty sets."
  [rev-set]
  (let [normalized (merge-sets empty-set rev-set)]
    (fn [] normalized)))

(defn combine-sources
  "Compose N revocation source functions into a single source.
   The returned function calls each input source and merges their
   outputs. Sources may return nil (treated as `empty-set`).

   (combine-sources static-a dynamic-b ...)"
  [& sources]
  (fn []
    (reduce (fn [acc s]
              (merge-sets acc (or (s) empty-set)))
            empty-set
            sources)))

;; ---------------------------------------------------------------------------
;; In-band collection
;; ---------------------------------------------------------------------------

(defn collect-in-band
  "Walk a seq of verified blocks, extracting :revocation assertions
   into a revocation set. Only :revocation typed assertions contribute
   — other types are ignored.

   Each :revocation assertion's statement is `[scope target]` where
   scope is `:assertion`, `:key`, or `:subject`."
  [blocks]
  (reduce
   (fn [acc block]
     (reduce
      (fn [acc2 a]
        (if (= :revocation (:type a))
          (let [stmt   (:statement a)
                scope  (nth stmt 0 nil)
                target (nth stmt 1 nil)]
            (case scope
              :assertion (update acc2 :ids      conj target)
              :key       (update acc2 :keys     conj target)
              :subject   (update acc2 :subjects conj target)
              acc2))
          acc2))
      acc
      (:assertions block)))
   empty-set
   blocks))

(defn collect-all
  "Collect a complete revocation set from in-band (blocks) and optional
   out-of-band (source function).

   Arities:
     (collect-all blocks)         — in-band only
     (collect-all blocks source)  — combined with an external source

   The source function takes zero arguments and returns a revocation
   set (or nil for empty)."
  ([blocks] (collect-all blocks nil))
  ([blocks source]
   (let [in-band (collect-in-band blocks)]
     (if source
       (merge-sets in-band (or (source) empty-set))
       in-band))))

;; ---------------------------------------------------------------------------
;; Checking
;; ---------------------------------------------------------------------------

(defn revoked?
  "Is `assertion` (from a block signed by `sayer-kid`) revoked by
   `rev-set`? Checks all three scopes:

   1. assertion's :id is in (:ids rev-set), OR
   2. sayer-kid is in (:keys rev-set), OR
   3. the first element of the statement (the subject, by convention)
      is in (:subjects rev-set)

   Returns truthy if any scope matches."
  [rev-set sayer-kid assertion]
  (or (contains? (:ids rev-set) (:id assertion))
      (contains? (:keys rev-set) sayer-kid)
      (let [subject (first (:statement assertion))]
        (and subject (contains? (:subjects rev-set) subject)))))
