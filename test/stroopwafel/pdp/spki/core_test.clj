(ns stroopwafel.pdp.spki.core-test
  "Phase 2 tests: context construction, add-* functions, pre-filter
   pipeline (sig → trust → temporal → revocation), decide, templates,
   and the verifier cap. Trust-closure (delegation) is Phase 3 and
   not tested here."
  (:require [clojure.test :refer [deftest is testing]]
            [stroopwafel.pdp.spki.core :as spki]
            [stroopwafel.pdp.spki.assertion :as a]
            [signet.key :as key]
            [com.github.franks42.uuidv7.core :as uuidv7]))

;; ---------------------------------------------------------------------------
;; Fixtures
;; ---------------------------------------------------------------------------

(def root-kp  (key/signing-keypair))
(def root-kid (key/kid root-kp))

(def other-kp  (key/signing-keypair))
(def other-kid (key/kid other-kp))

;; A standard capability template. Note unique variable names for the
;; shared-metadata positions — ?_ in stroopwafel's Datalog is a regular
;; variable, not a wildcard (would force unification if repeated).
(def capability-template
  '{:id   :tmpl/capability
    :head [:can ?subject ?action ?resource]
    :body [[?sayer ?ts ?nb ?na :capability ?id ?subject ?action ?resource]]})

(defn- cap-block
  [kp subject action resource & {:keys [not-before not-after]}]
  (a/sign-block kp
                (cond-> {:assertions [(a/assertion :capability
                                                   [subject action resource])]}
                  not-before (assoc :not-before not-before)
                  not-after  (assoc :not-after  not-after))))

;; ---------------------------------------------------------------------------
;; Context construction
;; ---------------------------------------------------------------------------

(deftest empty-context-shape
  (let [c (spki/context)]
    (is (= :stroopwafel.pdp.spki/context (:type c)))
    (is (= [] (:assertions c)))
    (is (= [] (:facts c)))
    (is (= #{} (:trust-roots c)))
    (is (= [] (:templates c)))
    (is (= 5000 (:clock-skew-ms c)))
    (is (fn? (:current-time-fn c)))))

(deftest context-options-override-defaults
  (let [c (spki/context {:clock-skew-ms 1000
                         :current-time-fn (constantly 42)})]
    (is (= 1000 (:clock-skew-ms c)))
    (is (= 42 ((:current-time-fn c))))))

;; ---------------------------------------------------------------------------
;; Ingestion functions
;; ---------------------------------------------------------------------------

(deftest add-trust-roots-accepts-string-set-or-seq
  (let [c1 (spki/add-trust-roots (spki/context) root-kid)
        c2 (spki/add-trust-roots (spki/context) #{root-kid other-kid})
        c3 (spki/add-trust-roots (spki/context) [root-kid other-kid])]
    (is (= #{root-kid} (:trust-roots c1)))
    (is (= #{root-kid other-kid} (:trust-roots c2)))
    (is (= #{root-kid other-kid} (:trust-roots c3)))))

(deftest add-facts-and-rules-accumulate
  (let [c (-> (spki/context)
              (spki/add-facts [[:a 1] [:b 2]])
              (spki/add-facts [[:c 3]])
              (spki/add-rules [{:id :r1 :head [:x] :body []}]))]
    (is (= [[:a 1] [:b 2] [:c 3]] (:facts c)))
    (is (= 1 (count (:rules c))))))

;; ---------------------------------------------------------------------------
;; Happy path: single bearer-ish assertion
;; ---------------------------------------------------------------------------

(deftest bearer-assertion-allowed
  (let [block  (cap-block root-kp "alice" :read "/data")
        result (-> (spki/context)
                   (spki/add-trust-roots root-kid)
                   (spki/with-templates [capability-template])
                   (spki/add-assertions block)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "alice" :read "/data"]]}]))]
    (is (:allowed? result))))

(deftest no-matching-policy-denied
  (let [block  (cap-block root-kp "alice" :read "/data")
        result (-> (spki/context)
                   (spki/add-trust-roots root-kid)
                   (spki/with-templates [capability-template])
                   (spki/add-assertions block)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "alice" :write "/data"]]}]))]
    (is (not (:allowed? result)))))

(deftest raw-fact-query-without-template
  (testing "templates are optional — raw fact matching works directly"
    (let [block  (cap-block root-kp "alice" :read "/data")
          result (-> (spki/context)
                     (spki/add-trust-roots root-kid)
                     (spki/add-assertions block)
                     (spki/decide
                      :policies [{:kind :allow
                                  :query [['?s '?t '?nb '?na
                                           :capability '?id
                                           "alice" :read "/data"]]}]))]
      (is (:allowed? result)))))

;; ---------------------------------------------------------------------------
;; Trust filter
;; ---------------------------------------------------------------------------

(deftest untrusted-sayer-dropped
  (let [block  (cap-block other-kp "mallory" :read "/data")
        result (-> (spki/context)
                   (spki/add-trust-roots root-kid)       ; only root trusted
                   (spki/with-templates [capability-template])
                   (spki/add-assertions block)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "mallory" :read "/data"]]}]))]
    (is (not (:allowed? result)))))

(deftest multiple-trust-roots
  (let [block1 (cap-block root-kp  "alice" :read "/data")
        block2 (cap-block other-kp "bob"   :read "/data")
        result (-> (spki/context)
                   (spki/add-trust-roots #{root-kid other-kid})
                   (spki/with-templates [capability-template])
                   (spki/add-assertions block1)
                   (spki/add-assertions block2)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "alice" :read "/data"]]}]))]
    (is (:allowed? result))))

;; ---------------------------------------------------------------------------
;; Temporal filter
;; ---------------------------------------------------------------------------

(deftest expired-block-dropped
  (let [block  (cap-block root-kp "alice" :read "/data"
                          :not-after (- (System/currentTimeMillis) 60000))
        result (-> (spki/context)
                   (spki/add-trust-roots root-kid)
                   (spki/with-templates [capability-template])
                   (spki/add-assertions block)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "alice" :read "/data"]]}]))]
    (is (not (:allowed? result)))))

(deftest not-yet-valid-block-dropped
  (let [block  (cap-block root-kp "alice" :read "/data"
                          :not-before (+ (System/currentTimeMillis) 60000))
        result (-> (spki/context)
                   (spki/add-trust-roots root-kid)
                   (spki/with-templates [capability-template])
                   (spki/add-assertions block)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "alice" :read "/data"]]}]))]
    (is (not (:allowed? result)))))

(deftest forever-block-allowed
  (testing "no :not-after at all = infinity, always passes temporal check"
    (let [block  (cap-block root-kp "alice" :read "/data")   ; no :not-after
          result (-> (spki/context)
                     (spki/add-trust-roots root-kid)
                     (spki/with-templates [capability-template])
                     (spki/add-assertions block)
                     (spki/decide
                      :policies [{:kind :allow
                                  :query [[:can "alice" :read "/data"]]}]))]
      (is (:allowed? result)))))

(deftest clock-skew-tolerated
  (testing "just-expired block with clock-skew tolerance passes"
    (let [now    (System/currentTimeMillis)
          ;; expired by 1 second; skew is 5 seconds; should pass
          block  (cap-block root-kp "alice" :read "/data"
                            :not-after (- now 1000))
          result (-> (spki/context {:current-time-fn (constantly now)})
                     (spki/add-trust-roots root-kid)
                     (spki/with-templates [capability-template])
                     (spki/add-assertions block)
                     (spki/decide
                      :policies [{:kind :allow
                                  :query [[:can "alice" :read "/data"]]}]))]
      (is (:allowed? result)))))

;; ---------------------------------------------------------------------------
;; Verifier cap (:max-block-ttl-ms)
;; ---------------------------------------------------------------------------

(deftest verifier-cap-tightens-long-lived-block
  (testing "a block signed with 1-hour :not-after, verifier cap tightens it"
    ;; Use clock-skew 0 and a fixed now to make the math deterministic.
    ;; Signing-ts is whatever sign-edn stamps; we freeze now at T+10s and
    ;; cap at 5s, so effective-not-after = signing-ts + 5s < now. Denied.
    (let [block    (cap-block root-kp "alice" :read "/data"
                              :not-after (+ (System/currentTimeMillis)
                                            (* 60 60 1000)))     ; 1 hour
          signing  (-> block :envelope :request-id uuidv7/extract-ts)
          frozen   (constantly (+ signing 10000))                 ; 10s after sign
          ctx      (-> (spki/context {:clock-skew-ms   0
                                      :current-time-fn frozen})
                       (spki/add-trust-roots root-kid)
                       (spki/with-templates [capability-template])
                       (spki/add-assertions block))
          policies [{:kind :allow :query [[:can "alice" :read "/data"]]}]]
      (testing "no cap → allowed (block valid for 1 hour, we're at +10s)"
        (is (:allowed? (spki/decide ctx :policies policies))))
      (testing "cap = 5000ms → denied (effective :not-after = signing + 5s, we're at +10s)"
        (is (not (:allowed? (spki/decide ctx
                                         :policies policies
                                         :max-block-ttl-ms 5000))))))))

;; ---------------------------------------------------------------------------
;; Revocation
;; ---------------------------------------------------------------------------

(deftest revocation-by-assertion-id
  (let [id    (random-uuid)
        cap-b (a/sign-block root-kp
                            {:assertions [(a/assertion :capability
                                                       id
                                                       ["alice" :read "/data"])]})
        rev-b (a/sign-block root-kp
                            {:assertions [(a/assertion :revocation
                                                       [:assertion id])]})
        result (-> (spki/context)
                   (spki/add-trust-roots root-kid)
                   (spki/with-templates [capability-template])
                   (spki/add-assertions cap-b)
                   (spki/add-assertions rev-b)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "alice" :read "/data"]]}]))]
    (is (not (:allowed? result))
        "Revoked-by-id assertion should be dropped from facts")))

(deftest revocation-by-sayer-key
  (let [cap-b  (cap-block other-kp "alice" :read "/data")
        rev-b  (a/sign-block root-kp
                             {:assertions [(a/assertion :revocation
                                                        [:key other-kid])]})
        result (-> (spki/context)
                   (spki/add-trust-roots #{root-kid other-kid})
                   (spki/with-templates [capability-template])
                   (spki/add-assertions cap-b)
                   (spki/add-assertions rev-b)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "alice" :read "/data"]]}]))]
    (is (not (:allowed? result))
        "All assertions from the revoked key are dropped")))

(deftest revocation-by-subject
  (let [cap-b  (cap-block root-kp "alice" :read "/data")
        rev-b  (a/sign-block root-kp
                             {:assertions [(a/assertion :revocation
                                                        [:subject "alice"])]})
        result (-> (spki/context)
                   (spki/add-trust-roots root-kid)
                   (spki/with-templates [capability-template])
                   (spki/add-assertions cap-b)
                   (spki/add-assertions rev-b)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "alice" :read "/data"]]}]))]
    (is (not (:allowed? result)))))

(deftest revocation-does-not-affect-other-subjects
  (let [cap-alice (cap-block root-kp "alice" :read "/data")
        cap-bob   (cap-block root-kp "bob"   :read "/data")
        rev-b     (a/sign-block root-kp
                                {:assertions [(a/assertion :revocation
                                                           [:subject "alice"])]})
        result (-> (spki/context)
                   (spki/add-trust-roots root-kid)
                   (spki/with-templates [capability-template])
                   (spki/add-assertions cap-alice)
                   (spki/add-assertions cap-bob)
                   (spki/add-assertions rev-b)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "bob" :read "/data"]]}]))]
    (is (:allowed? result)
        "Revoking 'alice' as a subject must not affect 'bob'")))

(deftest external-revocation-source
  (let [id    (random-uuid)
        cap-b (a/sign-block root-kp
                            {:assertions [(a/assertion :capability id
                                                       ["alice" :read "/data"])]})
        rev-src (fn [] {:ids #{id} :keys #{} :subjects #{}})
        result  (-> (spki/context)
                    (spki/add-trust-roots root-kid)
                    (spki/with-templates [capability-template])
                    (spki/with-revocation-source rev-src)
                    (spki/add-assertions cap-b)
                    (spki/decide
                     :policies [{:kind :allow
                                 :query [[:can "alice" :read "/data"]]}]))]
    (is (not (:allowed? result))
        "External revocation source contributes to the rev-set")))

;; ---------------------------------------------------------------------------
;; Injected facts + user rules
;; ---------------------------------------------------------------------------

(deftest injected-facts-visible-to-policies
  (testing "add-facts lands in the authorizer and is queryable by policies"
    (let [result (-> (spki/context)
                     (spki/add-facts [[:current-load 42]])
                     (spki/decide
                      :policies [{:kind :allow
                                  :query [[:current-load 42]]}]))]
      (is (:allowed? result)))))

(deftest user-rule-joins-across-assertion-and-injection
  (testing "a user rule can join assertion-derived facts with injected state"
    (let [block (cap-block root-kp "alice" :read "/data")
          rule  '{:id   :authorized-with-context
                  :head [:authorized ?subject]
                  :body [[:can ?subject :read "/data"]
                         [:business-hours true]]}
          result (-> (spki/context)
                     (spki/add-trust-roots root-kid)
                     (spki/with-templates [capability-template])
                     (spki/add-assertions block)
                     (spki/add-facts [[:business-hours true]])
                     (spki/add-rules [rule])
                     (spki/decide
                      :policies [{:kind :allow
                                  :query [[:authorized "alice"]]}]))]
      (is (:allowed? result)))))

;; ---------------------------------------------------------------------------
;; Multi-assertion block
;; ---------------------------------------------------------------------------

(deftest multi-assertion-block-all-surface
  (let [block (a/sign-block root-kp
                            {:assertions [(a/assertion :capability ["alice" :read "/data"])
                                          (a/assertion :capability ["alice" :write "/data"])
                                          (a/assertion :capability ["bob" :read "/data"])]})
        ctx   (-> (spki/context)
                  (spki/add-trust-roots root-kid)
                  (spki/with-templates [capability-template])
                  (spki/add-assertions block))]
    (is (:allowed? (spki/decide ctx :policies
                                [{:kind :allow :query [[:can "alice" :read "/data"]]}])))
    (is (:allowed? (spki/decide ctx :policies
                                [{:kind :allow :query [[:can "alice" :write "/data"]]}])))
    (is (:allowed? (spki/decide ctx :policies
                                [{:kind :allow :query [[:can "bob" :read "/data"]]}])))
    (is (not (:allowed? (spki/decide ctx :policies
                                     [{:kind :allow :query [[:can "bob" :write "/data"]]}]))))))

;; ---------------------------------------------------------------------------
;; Explain mode
;; ---------------------------------------------------------------------------

(deftest explain-mode-surfaces-rejected-assertions
  (let [good   (cap-block root-kp "alice" :read "/data")
        rogue  (cap-block other-kp "mallory" :read "/data")
        result (-> (spki/context)
                   (spki/add-trust-roots root-kid)
                   (spki/with-templates [capability-template])
                   (spki/add-assertions good)
                   (spki/add-assertions rogue)
                   (spki/decide
                    :policies [{:kind :allow
                                :query [[:can "alice" :read "/data"]]}]
                    :explain? true))]
    (is (:allowed? result))
    (is (contains? result :rejected))
    (is (some #(= :untrusted-sayer (:reason %)) (:rejected result))
        "The rogue block is in :rejected with :untrusted-sayer")))

(deftest silent-drop-does-not-fail-otherwise-valid-request
  (testing "one bad assertion does not sink a request another valid assertion would allow"
    (let [good     (cap-block root-kp "alice" :read "/data")
          expired  (cap-block root-kp "alice" :read "/data"
                              :not-after (- (System/currentTimeMillis) 60000))
          result   (-> (spki/context)
                       (spki/add-trust-roots root-kid)
                       (spki/with-templates [capability-template])
                       (spki/add-assertions good)
                       (spki/add-assertions expired)
                       (spki/decide
                        :policies [{:kind :allow
                                    :query [[:can "alice" :read "/data"]]}]))]
      (is (:allowed? result)
          "SPKI compositionality: bad assertion dropped, good one still applies"))))

;; ---------------------------------------------------------------------------
;; Invalid signatures
;; ---------------------------------------------------------------------------

(deftest tampered-block-silently-dropped
  (let [block     (cap-block root-kp "alice" :read "/data")
        tampered  (assoc-in block
                            [:envelope :message :assertions 0 :statement]
                            ["mallory" :read "/data"])
        result    (-> (spki/context)
                      (spki/add-trust-roots root-kid)
                      (spki/with-templates [capability-template])
                      (spki/add-assertions tampered)
                      (spki/decide
                       :policies [{:kind :allow
                                   :query [[:can "mallory" :read "/data"]]}]
                       :explain? true))]
    (is (not (:allowed? result)))
    (is (some #(= :invalid-signature (:reason %)) (:rejected result)))))
