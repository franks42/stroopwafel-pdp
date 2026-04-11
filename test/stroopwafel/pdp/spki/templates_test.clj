(ns stroopwafel.pdp.spki.templates-test
  "Phase 4 tests: standard templates work end-to-end through the PDP
   and compose cleanly into higher-level policies (SDSI-style name
   resolution, audit queries, etc.)."
  (:require [clojure.test :refer [deftest is testing]]
            [stroopwafel.pdp.spki.core :as spki]
            [stroopwafel.pdp.spki.assertion :as a]
            [stroopwafel.pdp.spki.templates :as tmpl]
            [signet.key :as key]))

;; ---------------------------------------------------------------------------
;; Fixtures
;; ---------------------------------------------------------------------------

(def root-kp  (key/signing-keypair))
(def root-kid (key/kid root-kp))

(def alice-kp  (key/signing-keypair))
(def alice-kid (key/kid alice-kp))

(defn- base-ctx []
  (-> (spki/context)
      (spki/add-trust-roots root-kid)
      (spki/with-templates tmpl/standard)))

;; ---------------------------------------------------------------------------
;; :capability template
;; ---------------------------------------------------------------------------

(deftest capability-template-allows-matching-request
  (let [block (a/sign-block root-kp
                            {:assertions [(a/assertion :capability
                                                       ["alice" :read "/data"])]})
        r     (-> (base-ctx)
                  (spki/add-assertions block)
                  (spki/decide
                   :policies [{:kind :allow
                               :query [[:can "alice" :read "/data"]]}]))]
    (is (:allowed? r))))

(deftest capability-template-denies-non-matching-request
  (let [block (a/sign-block root-kp
                            {:assertions [(a/assertion :capability
                                                       ["alice" :read "/data"])]})
        r     (-> (base-ctx)
                  (spki/add-assertions block)
                  (spki/decide
                   :policies [{:kind :allow
                               :query [[:can "bob" :read "/data"]]}]))]
    (is (not (:allowed? r)))))

(deftest capability-constrained-template
  (testing "4-arity :capability with a constraints map exposes all 4 args"
    (let [block (a/sign-block
                 root-kp
                 {:assertions [(a/assertion :capability
                                            ["alice" :trade "AAPL"
                                             {:max-qty 100}])]})
          rule  '{:id   :within-limits
                  :head [:allowed-trade ?subject ?sym]
                  :body [[:can ?subject :trade ?sym ?c]]}
          r     (-> (base-ctx)
                    (spki/add-assertions block)
                    (spki/add-rules [rule])
                    (spki/decide
                     :policies [{:kind :allow
                                 :query [[:allowed-trade "alice" "AAPL"]]}]))]
      (is (:allowed? r)))))

;; ---------------------------------------------------------------------------
;; :name-binding template
;; ---------------------------------------------------------------------------

(deftest name-binding-template
  (let [block (a/sign-block
               root-kp
               {:assertions [(a/assertion :name-binding [alice-kid "ops-team"])]})
        rule  '{:id   :alice-in-ops
                :head [:in-group ?key ?group]
                :body [[:named ?key ?group]]}
        r     (-> (base-ctx)
                  (spki/add-assertions block)
                  (spki/add-rules [rule])
                  (spki/decide
                   :policies [{:kind :allow
                               :query [[:in-group alice-kid "ops-team"]]}]))]
    (is (:allowed? r))))

;; ---------------------------------------------------------------------------
;; SDSI-style name resolution — capability + name-binding composition
;; ---------------------------------------------------------------------------

(deftest sdsi-name-resolution-integration
  (testing "root says: alice-kid is in 'ops-team'; ops-team can :restart /api.
            A user rule joins the two into an authorized predicate.
            Policy matches → allow."
    (let [bindings-block
          (a/sign-block root-kp
                        {:assertions [(a/assertion :name-binding
                                                   [alice-kid "ops-team"])]})
          capability-block
          (a/sign-block root-kp
                        {:assertions [(a/assertion :capability
                                                   ["ops-team" :restart "/api"])]})
          authorized-rule
          '{:id   :authorized-via-group
            :head [:authorized ?key ?action ?resource]
            :body [[:named ?key ?group]
                   [:can ?group ?action ?resource]]}
          r (-> (base-ctx)
                (spki/add-assertions bindings-block)
                (spki/add-assertions capability-block)
                (spki/add-rules [authorized-rule])
                (spki/decide
                 :policies [{:kind :allow
                             :query [[:authorized alice-kid :restart "/api"]]}]))]
      (is (:allowed? r)))))

(deftest sdsi-non-member-denied
  (let [bindings-block
        (a/sign-block root-kp
                      {:assertions [(a/assertion :name-binding
                                                 [alice-kid "ops-team"])]})
        capability-block
        (a/sign-block root-kp
                      {:assertions [(a/assertion :capability
                                                 ["ops-team" :restart "/api"])]})
        authorized-rule
        '{:id   :authorized-via-group
          :head [:authorized ?key ?action ?resource]
          :body [[:named ?key ?group]
                 [:can ?group ?action ?resource]]}
        bob-kid "urn:signet:pk:ed25519:not-a-real-key-just-for-the-test-42"
        r (-> (base-ctx)
              (spki/add-assertions bindings-block)
              (spki/add-assertions capability-block)
              (spki/add-rules [authorized-rule])
              (spki/decide
               :policies [{:kind :allow
                           :query [[:authorized bob-kid :restart "/api"]]}]))]
    (is (not (:allowed? r))
        "Bob is not in ops-team → no :named entry → policy fails")))

;; ---------------------------------------------------------------------------
;; :delegation template (audit query)
;; ---------------------------------------------------------------------------

(deftest delegation-template-audit
  (testing "query: who delegated :capability rights?"
    (let [delegate-kp  (key/signing-keypair)
          delegate-kid (key/kid delegate-kp)
          del-block    (a/sign-block
                        root-kp
                        {:assertions [(a/assertion :delegation
                                                   [delegate-kid :capability])]})
          ;; Intermediary signs a capability to exercise the pipeline
          cap-block    (a/sign-block
                        delegate-kp
                        {:assertions [(a/assertion :capability
                                                   ["dave" :read "/data"])]})
          r (-> (base-ctx)
                (spki/add-assertions del-block)
                (spki/add-assertions cap-block)
                (spki/decide
                 :policies [{:kind :allow
                             :query [[:delegated root-kid delegate-kid :capability]]}]))]
      (is (:allowed? r) "The delegation assertion should surface as a fact"))))

;; ---------------------------------------------------------------------------
;; :revocation templates (surfaced for audit)
;; ---------------------------------------------------------------------------

(deftest revocation-template-surfaces-revoked-ids
  (testing "revocation assertions for audit queries — even though the
            pre-filter already dropped the targeted assertion, the
            revocation itself is still in the fact store"
    (let [target-id (random-uuid)
          rev-block (a/sign-block
                     root-kp
                     {:assertions [(a/assertion :revocation
                                                [:assertion target-id])]})
          r (-> (base-ctx)
                (spki/add-assertions rev-block)
                (spki/decide
                 :policies [{:kind :allow
                             :query [[:revoked-assertion target-id]]}]))]
      (is (:allowed? r)))))

(deftest revocation-subject-template
  (let [rev-block (a/sign-block
                   root-kp
                   {:assertions [(a/assertion :revocation [:subject "mallory"])]})
        r (-> (base-ctx)
              (spki/add-assertions rev-block)
              (spki/decide
               :policies [{:kind :allow
                           :query [[:revoked-subject "mallory"]]}]))]
    (is (:allowed? r))))

;; ---------------------------------------------------------------------------
;; Template bundle subsetting
;; ---------------------------------------------------------------------------

(deftest subset-bundle-capabilities-only
  (testing "a service that only uses :capability can register just
            the capability templates"
    (let [cap-block  (a/sign-block
                      root-kp
                      {:assertions [(a/assertion :capability
                                                 ["alice" :read "/data"])]})
          name-block (a/sign-block
                      root-kp
                      {:assertions [(a/assertion :name-binding
                                                 [alice-kid "ops-team"])]})
          ctx (-> (spki/context)
                  (spki/add-trust-roots root-kid)
                  (spki/with-templates tmpl/capabilities-only)
                  (spki/add-assertions cap-block)
                  (spki/add-assertions name-block))]
      (testing ":can fires (template registered)"
        (is (:allowed? (spki/decide ctx :policies
                                    [{:kind :allow
                                      :query [[:can "alice" :read "/data"]]}]))))
      (testing ":named does NOT fire (template not registered) even though
                the fact is in the store"
        (is (not (:allowed? (spki/decide ctx :policies
                                         [{:kind :allow
                                           :query [[:named alice-kid "ops-team"]]}]))))))))

;; ---------------------------------------------------------------------------
;; Raw fact matching still works alongside templates
;; ---------------------------------------------------------------------------

(deftest raw-patterns-coexist-with-templates
  (testing "users can mix raw positional patterns with template-derived predicates"
    (let [block (a/sign-block
                 root-kp
                 {:assertions [(a/assertion :capability
                                            ["alice" :read "/data"])]})
          ;; Raw match against the 9-position stored fact
          raw-rule '{:id   :raw-match
                     :head [:raw-cap ?subject]
                     :body [[?_s ?_ts ?_nb ?_na :capability ?_id ?subject :read "/data"]]}
          r (-> (base-ctx)
                (spki/add-assertions block)
                (spki/add-rules [raw-rule])
                (spki/decide
                 :policies [{:kind :allow
                             :query [[:raw-cap "alice"]]}]))]
      (is (:allowed? r)))))
