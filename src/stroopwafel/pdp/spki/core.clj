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
            [stroopwafel.pdp.spki.assertion :as assertion]))

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
  "Register primordial trust-root sayer kids. Accepts a kid URN
   string, a set/sequence of strings.

   Phase 2: flat set, no scoping.
   Phase 3: will extend to scoped trust maps with delegation."
  [ctx roots]
  (update ctx :trust-roots into
          (cond
            (string? roots)     [roots]
            (set? roots)        roots
            (sequential? roots) roots
            :else (throw (ex-info "trust-roots must be a kid URN, set, or sequence"
                                  {:got roots})))))

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

(defn- collect-revocations
  "Scan verified blocks' assertions for :revocation statements,
   combined with any out-of-band source. Returns
   {:ids #{} :keys #{} :subjects #{}}."
  [verified-blocks rev-src]
  (let [base     {:ids #{} :keys #{} :subjects #{}}
        in-band  (reduce
                  (fn [acc vb]
                    (reduce
                     (fn [acc2 a]
                       (if (= :revocation (:type a))
                         (let [[scope target] (:statement a)]
                           (case scope
                             :assertion (update acc2 :ids conj target)
                             :key       (update acc2 :keys conj target)
                             :subject   (update acc2 :subjects conj target)
                             acc2))
                         acc2))
                     acc
                     (:assertions vb)))
                  base
                  verified-blocks)
        external (when rev-src (rev-src))]
    (cond-> in-band
      (:ids external)      (update :ids into (:ids external))
      (:keys external)     (update :keys into (:keys external))
      (:subjects external) (update :subjects into (:subjects external)))))

(defn- revoked?
  "Is this assertion revoked? Checks id, sayer-key, and subject
   (first element of the statement, by convention)."
  [rev-set sayer-kid a]
  (or (contains? (:ids rev-set) (:id a))
      (contains? (:keys rev-set) sayer-kid)
      (let [subject (first (:statement a))]
        (and subject (contains? (:subjects rev-set) subject)))))

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
  "Run passes 1–5 on the raw signed blocks in the context.

   Pass 1: signature verification (drops invalid sigs)
   Pass 2: trust filter (Phase 2: flat primordial set)
   Pass 3: temporal filter (with :max-block-ttl-ms verifier cap)
   Pass 4: collect revocation set (in-band + out-of-band)
   Pass 5: filter assertions by revocation + expand to flat facts

   Returns {:facts [...] :rejected [...]}."
  [ctx max-block-ttl-ms]
  (let [now   ((:current-time-fn ctx))
        skew  (:clock-skew-ms ctx)
        roots (:trust-roots ctx)
        ;; Pass 1: signature verification
        verified
        (reduce
         (fn [acc signed-block]
           (let [r (assertion/verify-block signed-block)]
             (if (:valid? r)
               (update acc :verified conj r)
               (update acc :rejected conj
                       {:reason :invalid-signature :block signed-block}))))
         {:verified [] :rejected []}
         (:assertions ctx))
        ;; Pass 2: trust filter (flat primordial set — Phase 2)
        {trusted true untrusted false}
        (group-by #(contains? roots (:sayer %)) (:verified verified))
        rejected-untrusted
        (mapv #(hash-map :reason :untrusted-sayer :sayer (:sayer %)) untrusted)
        ;; Pass 3: temporal filter (with verifier cap)
        {temporally-valid true temporally-invalid false}
        (group-by
         (fn [vb]
           (let [na-eff (effective-not-after (:not-after vb)
                                             (:signing-ts vb)
                                             max-block-ttl-ms)]
             (temporally-valid? (:not-before vb) na-eff now skew)))
         (or trusted []))
        rejected-temporal
        (mapv #(hash-map :reason :temporally-invalid :sayer (:sayer %)) temporally-invalid)
        ;; Attach the effective-not-after to each surviving block
        valid-blocks
        (mapv (fn [vb]
                (assoc vb :effective-not-after
                       (effective-not-after (:not-after vb)
                                            (:signing-ts vb)
                                            max-block-ttl-ms)))
              (or temporally-valid []))
        ;; Pass 4: collect revocation set from valid blocks + external
        rev-set (collect-revocations valid-blocks (:revocation-src ctx))
        ;; Pass 5: expand surviving assertions, dropping revoked ones
        {facts :facts rejected-rev :rejected}
        (reduce
         (fn [acc vb]
           (reduce
            (fn [acc2 a]
              (if (revoked? rev-set (:sayer vb) a)
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
         valid-blocks)]
    {:facts    facts
     :rejected (into (into (into (:rejected verified)
                                 rejected-untrusted)
                           rejected-temporal)
                     rejected-rev)}))

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
