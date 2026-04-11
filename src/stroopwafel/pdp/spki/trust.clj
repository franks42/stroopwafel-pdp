(ns stroopwafel.pdp.spki.trust
  "Trust closure with delegation fixpoint for the SPKI/SDSI PDP.

   A trust entry is a map:
     {:kid <kid URN>
      :for-types <:all or set of assertion-type keywords>
      :not-after <epoch-ms or nil for infinity>
      :origin <:primordial or :delegated>}

   Multiple entries may exist for the same kid (one primordial, several
   delegated). trusted-for? iterates and returns true if ANY entry
   covers the requested type at the given time. This automatically
   implements the 'widen' semantics (pinned decision §11 #6): a
   primordial trust-root's effective scope is the union of its
   primordial grant and any delegations that also reach it.

   Delegation semantics:
     - A sayer trusted for type T can issue :delegation assertions
       for type T to any kid (no separate :delegation grant needed).
     - The delegated entry's :for-types is the intersection of the
       delegator's scope and the delegation's stated type.
     - The delegated entry's :not-after is the MIN of the delegator's
       own :not-after and the delegation block's :not-after
       (attenuation — a delegate can never outlive the delegator).

   Phase 3 scope: type-level delegation. Resource/action scoping (e.g.,
   'delegate :capability for resources under /api/service only') is
   deferred — delegation assertions carry only a delegate kid and a
   type keyword (or :all)."
  (:refer-clojure :exclude [resolve]))

;; ---------------------------------------------------------------------------
;; Primordial trust normalization
;; ---------------------------------------------------------------------------

(defn- ->primordial-entries
  "Normalize primordial trust-roots into a vector of trust entries.

   Accepts:
     - set/seq of kid URN strings — each becomes {:for-types :all :not-after nil}
     - map {kid → {:for-types :not-after}}"
  [primordial]
  (cond
    (map? primordial)
    (mapv (fn [[kid spec]]
            {:kid       kid
             :for-types (or (:for-types spec) :all)
             :not-after (:not-after spec)
             :origin    :primordial})
          primordial)

    (coll? primordial)
    (mapv (fn [kid]
            {:kid       kid
             :for-types :all
             :not-after nil
             :origin    :primordial})
          primordial)

    :else []))

;; ---------------------------------------------------------------------------
;; The trusted-for? predicate
;; ---------------------------------------------------------------------------

(defn- entry-active?
  "Is this trust entry temporally active at `now` (with `skew`)?"
  [entry now skew]
  (or (nil? (:not-after entry))
      (< (- now skew) (long (:not-after entry)))))

(defn- entry-covers-type?
  [entry type]
  (let [for-types (:for-types entry)]
    (or (= :all for-types)
        (and (set? for-types) (contains? for-types type)))))

(defn trusted-for?
  "Is `sayer-kid` trusted for assertions of type `type` at `now`
   (with clock-skew `skew`)? Returns truthy iff any entry in
   `trust-entries` matches the sayer and covers the type and is
   still temporally active."
  [trust-entries sayer-kid type now skew]
  (some (fn [e]
          (and (= (:kid e) sayer-kid)
               (entry-covers-type? e type)
               (entry-active? e now skew)))
        trust-entries))

;; ---------------------------------------------------------------------------
;; Delegation entry construction
;; ---------------------------------------------------------------------------

(defn- min-not-after
  "Take the MIN of two :not-after values, treating nil as infinity."
  [a b]
  (cond
    (nil? a) b
    (nil? b) a
    :else    (min (long a) (long b))))

(defn- intersect-types
  "Compute the intersection of a delegator's :for-types and a
   delegation's stated type. Returns a normalized :for-types value
   (:all or a set), or nil if the delegator cannot grant the stated
   type at all."
  [delegator-types delegation-type]
  (cond
    ;; Delegator has full rights; delegation narrows to one type
    (and (= :all delegator-types) (not= :all delegation-type))
    #{delegation-type}

    ;; Delegator has full rights; delegation also full
    (and (= :all delegator-types) (= :all delegation-type))
    :all

    ;; Delegator has restricted rights; delegation wants :all
    ;; → delegate gets whatever delegator has
    (and (set? delegator-types) (= :all delegation-type))
    delegator-types

    ;; Both restricted — intersect
    (and (set? delegator-types) (contains? delegator-types delegation-type))
    #{delegation-type}

    ;; Delegator can't grant the stated type
    :else nil))

(defn- build-delegated-entry
  "Construct a trust entry for a delegate based on a delegator's
   trust and a :delegation assertion. Returns nil if the delegation
   is out-of-scope for the delegator."
  [delegator-entry delegation-block delegation-assertion]
  (let [statement (:statement delegation-assertion)
        delegate  (nth statement 0 nil)
        del-type  (nth statement 1 :all)
        new-types (intersect-types (:for-types delegator-entry) del-type)]
    (when (and delegate new-types)
      {:kid       delegate
       :for-types new-types
       :not-after (min-not-after (:not-after delegator-entry)
                                 (:not-after delegation-block))
       :origin    :delegated})))

;; ---------------------------------------------------------------------------
;; The fixpoint
;; ---------------------------------------------------------------------------

(defn- entry= [a b]
  (and (= (:kid a) (:kid b))
       (= (:for-types a) (:for-types b))
       (= (:not-after a) (:not-after b))))

(defn- add-unique [entries entry]
  (if (some #(entry= % entry) entries)
    entries
    (conj entries entry)))

(defn- process-block
  "Walk one verified block's :delegation assertions and contribute
   new trust entries from any active delegator. The intersect-types
   step inside build-delegated-entry handles the scope narrowing, so
   this function only needs to check: (a) the delegator is active
   right now, and (b) for a specific-type delegation the delegator
   actually has that type in scope.

   A delegator delegating :all is always allowed if they're active —
   they're delegating 'whatever I have', which the intersection will
   compute correctly. A delegator delegating a specific type must
   already cover that type."
  [entries block now skew]
  (reduce
   (fn [acc a]
     (if (not= :delegation (:type a))
       acc
       (let [del-type  (nth (:statement a) 1 :all)
             delegator (some (fn [e]
                               (and (= (:kid e) (:sayer block))
                                    (entry-active? e now skew)
                                    (or (= :all del-type)
                                        (entry-covers-type? e del-type))
                                    e))
                             acc)]
         (if-not delegator
           acc
           (if-let [new-entry (build-delegated-entry delegator block a)]
             (add-unique acc new-entry)
             acc)))))
   entries
   (:assertions block)))

(defn resolve
  "Compute the trust closure from primordial trust-roots and
   temporally-valid verified blocks.

   Arguments:
     primordial — set/seq of kid URNs OR map {kid → {:for-types :not-after}}
     blocks     — temporally-valid verified blocks from the pre-filter
                  (each with :sayer :not-after :assertions [...])
     now        — current epoch-ms
     skew       — clock skew tolerance in ms

   Returns: vector of trust entries. Fixpoint converges in at most
   (count blocks) passes."
  [primordial blocks now skew]
  (let [initial (->primordial-entries primordial)]
    (loop [entries initial
           guard   (inc (count blocks))] ; termination safety
      (if (zero? guard)
        entries
        (let [next-entries (reduce (fn [e b] (process-block e b now skew))
                                   entries
                                   blocks)]
          (if (= (count next-entries) (count entries))
            entries
            (recur next-entries (dec guard))))))))
