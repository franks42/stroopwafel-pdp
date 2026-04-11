(ns stroopwafel.pdp.spki.core
  "SPKI/SDSI-shaped PDP: context builder, assertion ingestion, the
   pre-filter pipeline, and decide.

   Usage:
     (-> (context)
         (add-trust-roots    #{authority-kid})
         (with-templates     tmpl/standard)
         (add-assertions     signed-block)
         (add-facts          [[:current-time (System/currentTimeMillis)]])
         (decide :policies [{:kind :allow
                             :query [[:can \"alice\" :read \"/data\"]]}]))

   Phase 2 scope: passes 1–5 of the pre-filter (sig → trust → temporal
   → revocation → expand). Trust is a flat primordial set — delegation
   closure is Phase 3. The pipeline is otherwise complete end-to-end.

   See docs/assertion-api-proposal.md for the full design."
  (:require [stroopwafel.core :as engine]
            [stroopwafel.pdp.spki.assertion :as assertion]
            [stroopwafel.pdp.spki.revocation :as revocation]
            [stroopwafel.pdp.spki.trust :as trust]))

;; ---------------------------------------------------------------------------
;; Context constructor
;; ---------------------------------------------------------------------------

(defn context
  "Create an empty SPKI PDP context.

   Options:
     :clock-skew-ms   — symmetric clock skew tolerance (default 5000)
     :current-time-fn — zero-arg fn returning epoch-ms
                        (default #(System/currentTimeMillis))"
  ([] (context {}))
  ([opts]
   {:type            :stroopwafel.pdp.spki/context
    :assertions      []            ; raw signed blocks before pre-filter
    :facts           []            ; injected, unsigned, service-local
    :rules           []            ; user-supplied rules (authorizer)
    :checks          []            ; user-supplied checks (authorizer)
    :trust-roots     #{}           ; primordial trusted sayer kids
    :templates       []            ; derivation templates (authorizer rules)
    :revocation-src  nil           ; optional () → {:ids :keys :subjects}
    :clock-skew-ms   (or (:clock-skew-ms opts) 5000)
    :current-time-fn (or (:current-time-fn opts)
                         #(System/currentTimeMillis))
    :errors          []}))

;; ---------------------------------------------------------------------------
;; Ingestion / configuration
;; ---------------------------------------------------------------------------

(defn add-assertions
  "Add a signed assertion block. Verification is lazy — the block is
   checked when decide runs, not at add time, so context building
   stays cheap."
  [ctx signed-block]
  (update ctx :assertions conj signed-block))

(def add-assertion
  "Alias for add-assertions — single-block convenience."
  add-assertions)

(defn add-trust-roots
  "Register primordial trust-root sayers.

   Accepts:
     - a kid URN string — trusted for :all assertion types, forever
     - a set/sequence of kid URN strings — same
     - a map {kid → {:for-types <:all or set> :not-after <epoch-ms or nil>}}
       — scoped primordial trust

   Primordial trust is a floor: delegation can only raise a primordial
   root's effective scope (pinned decision §11 #6), never narrow it.
   Multiple calls accumulate.

   The context stores trust-roots as either a set of strings (simple
   case) or a map (scoped case); both forms are accepted by the trust
   closure at decide time."
  [ctx roots]
  (cond
    (string? roots)
    (update ctx :trust-roots
            (fn [existing]
              (if (map? existing)
                (assoc existing roots {:for-types :all :not-after nil})
                (conj (or existing #{}) roots))))

    (map? roots)
    (update ctx :trust-roots
            (fn [existing]
              (merge (if (map? existing)
                       existing
                       ;; Promote an existing set to a map form so we
                       ;; can merge in the new scoped entries without
                       ;; losing earlier unscoped entries.
                       (into {} (map #(vector % {:for-types :all :not-after nil})
                                     (or existing #{}))))
                     roots)))

    (or (set? roots) (sequential? roots))
    (reduce add-trust-roots ctx roots)

    :else
    (throw (ex-info "trust-roots must be a kid URN, set/seq, or map"
                    {:got roots}))))

(defn with-templates
  "Register derivation templates. These are Datalog rules that unpack
   assertion tuples into clean named predicates (e.g., [:can ?s ?a ?r]
   from a :capability assertion). Added to the authorizer rules at
   decide time."
  [ctx templates]
  (update ctx :templates into templates))

(defn with-revocation-source
  "Register a function that returns {:ids #{...} :keys #{...} :subjects #{...}}
   representing live out-of-band revocations. Called once per decide.
   In-band :revocation assertions inside blocks are always collected
   regardless of whether this is set."
  [ctx f]
  (assoc ctx :revocation-src f))

(defn add-facts
  "Add injected service-local facts (current time, request state,
   account balances, etc.). These are unsigned and implicitly trusted
   — they come from the service itself. Kept separate from
   assertion-derived facts."
  [ctx facts]
  (update ctx :facts into facts))

(defn add-rules
  "Add user-supplied Datalog rules to the authorizer scope."
  [ctx rules]
  (update ctx :rules into rules))

(defn add-checks
  "Add user-supplied Datalog checks to the authorizer scope."
  [ctx checks]
  (update ctx :checks into checks))

;; ---------------------------------------------------------------------------
;; Pre-filter pipeline
;; ---------------------------------------------------------------------------

(def ^:private +infinity+
  "Sentinel for 'no upper bound' when a block's :not-after is nil.
   Stored in the Datalog fact so queries can compare temporally
   without special-casing nil."
  Long/MAX_VALUE)

(defn- temporally-valid?
  "Is current-time within [not-before - skew, not-after + skew)?
   not-after may be nil or Long/MAX_VALUE for 'no upper bound'."
  [not-before not-after now skew]
  (let [na (or not-after +infinity+)
        ;; Avoid overflow when not-after is MAX_VALUE + skew
        na-ceiling (if (> na (- Long/MAX_VALUE skew))
                     Long/MAX_VALUE
                     (+ na skew))]
    (and (<= (- not-before skew) now)
         (< now na-ceiling))))

(defn- effective-not-after
  "Apply the verifier cap :max-block-ttl-ms to a stated :not-after.
   Verifiers can only tighten, never loosen (§5.2). Returns epoch-ms
   or nil for infinity."
  [stated-not-after signing-ts max-ttl-ms]
  (let [capped (when max-ttl-ms (+ signing-ts (long max-ttl-ms)))]
    (cond
      (and capped stated-not-after) (min (long stated-not-after) capped)
      capped                        capped
      :else                         stated-not-after)))

(defn- expand-assertion
  "Flatten a verified assertion into a Datalog fact tuple:
     [sayer signing-ts not-before not-after type id & statement]
   not-after is stored as Long/MAX_VALUE when the block has no
   upper bound, so Datalog comparisons don't have to special-case nil."
  [sayer signing-ts not-before not-after a]
  (into [sayer signing-ts not-before (or not-after +infinity+)
         (:type a) (:id a)]
        (:statement a)))

(defn- pre-filter
  "Run the full pipeline on the raw signed blocks in the context.

   Pass 1: signature verification (drops invalid sigs)
   Pass 2: temporal filter (with :max-block-ttl-ms verifier cap)
   Pass 3: resolve trust closure from primordial + delegation
   Pass 4: per-assertion trust check — a block's sayer may be trusted
           for some assertion types but not others
   Pass 5: collect revocation set (in-band + out-of-band) from
           trust-filtered assertions
   Pass 6: drop revoked assertions + expand to flat facts

   Note the ordering change from Phase 2: temporal filter runs BEFORE
   trust filter so that expired delegation blocks don't contribute to
   the trust closure. And trust is now per-assertion, not per-block,
   because a delegated sayer may be trusted for some types but not
   others.

   Returns {:facts [...] :rejected [...]}."
  [ctx max-block-ttl-ms]
  (let [now   ((:current-time-fn ctx))
        skew  (:clock-skew-ms ctx)
        roots (:trust-roots ctx)

        ;; Pass 1: signature verification
        {verified :verified rejected-sig :rejected}
        (reduce
         (fn [acc signed-block]
           (let [r (assertion/verify-block signed-block)]
             (if (:valid? r)
               (update acc :verified conj r)
               (update acc :rejected conj {:reason :invalid-signature}))))
         {:verified [] :rejected []}
         (:assertions ctx))

        ;; Pass 2: temporal filter (with verifier cap)
        valid-blocks
        (for [vb verified
              :let [na-eff (effective-not-after (:not-after vb)
                                                (:signing-ts vb)
                                                max-block-ttl-ms)]
              :when (temporally-valid? (:not-before vb) na-eff now skew)]
          (assoc vb :effective-not-after na-eff))
        rejected-temporal
        (for [vb verified
              :let [na-eff (effective-not-after (:not-after vb)
                                                (:signing-ts vb)
                                                max-block-ttl-ms)]
              :when (not (temporally-valid? (:not-before vb) na-eff now skew))]
          {:reason :temporally-invalid :sayer (:sayer vb)})

        ;; Pass 3: resolve trust closure (primordial + delegation fixpoint)
        trust-entries (trust/resolve roots valid-blocks now skew)

        ;; Pass 4: per-assertion trust check.
        ;; An assertion survives iff its block's sayer is trusted for
        ;; that assertion's type at 'now'. Silent drop per §11 decision.
        {trust-survivors :facts rejected-trust :rejected}
        (reduce
         (fn [acc vb]
           (reduce
            (fn [acc2 a]
              (if (trust/trusted-for? trust-entries (:sayer vb) (:type a) now skew)
                (update acc2 :facts conj {:block vb :assertion a})
                (update acc2 :rejected conj
                        {:reason :untrusted-for-type
                         :sayer  (:sayer vb)
                         :type   (:type a)
                         :id     (:id a)})))
            acc
            (:assertions vb)))
         {:facts [] :rejected []}
         valid-blocks)

        ;; Pass 5: collect revocation set from trust-filtered assertions.
        ;; Re-group survivors by block so the revocation collector sees
        ;; the block shape it expects.
        survivor-blocks
        (->> trust-survivors
             (group-by :block)
             (mapv (fn [[block pairs]]
                     (assoc block :assertions (mapv :assertion pairs)))))
        rev-set (revocation/collect-all survivor-blocks (:revocation-src ctx))

        ;; Pass 6: expand surviving assertions, dropping revoked ones
        {facts :facts rejected-rev :rejected}
        (reduce
         (fn [acc vb]
           (reduce
            (fn [acc2 a]
              (if (revocation/revoked? rev-set (:sayer vb) a)
                (update acc2 :rejected conj
                        {:reason :revoked :sayer (:sayer vb) :id (:id a)})
                (update acc2 :facts conj
                        (expand-assertion (:sayer vb)
                                          (:signing-ts vb)
                                          (:not-before vb)
                                          (:effective-not-after vb)
                                          a))))
            acc
            (:assertions vb)))
         {:facts [] :rejected []}
         survivor-blocks)]
    {:facts    facts
     :rejected (vec (concat rejected-sig rejected-temporal
                            rejected-trust rejected-rev))}))

;; ---------------------------------------------------------------------------
;; Decide
;; ---------------------------------------------------------------------------

(defn decide
  "Run the pre-filter pipeline and evaluate the policy.

   Options:
     :policies         — ordered allow/deny policies (first match wins)
     :rules            — extra authorizer rules (in addition to templates)
     :checks           — extra authorizer checks
     :explain?         — include proof tree + rejected assertions
     :max-block-ttl-ms — verifier cap on block :not-after (§5.2)

   Returns:
     {:allowed? boolean}
     or {:allowed? boolean :explain ... :rejected ...}   (explain? mode)
     or {:allowed? false :errors [...]}                  (context errors)"
  [ctx & {:keys [policies rules checks explain? max-block-ttl-ms]}]
  (if (seq (:errors ctx))
    {:allowed? false :errors (:errors ctx)}
    (let [{:keys [facts rejected]} (pre-filter ctx max-block-ttl-ms)
          token      {:blocks [{:facts  facts
                                :rules  []
                                :checks []}]}
          authorizer {:facts    (vec (:facts ctx))
                      :rules    (vec (concat (:templates ctx)
                                             (:rules ctx)
                                             (or rules [])))
                      :checks   (vec (concat (:checks ctx) (or checks [])))
                      :policies (vec (or policies []))}
          result     (engine/evaluate token
                                      :explain?   explain?
                                      :authorizer authorizer)]
      (cond-> {:allowed? (boolean (:valid? result))}
        explain? (assoc :explain  (:explain result)
                        :rejected rejected)))))
