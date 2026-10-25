(ns stroopwafel.pdp.core-test
  "Integration tests: signet signs → PDP extracts → stroopwafel decides.

   These tests prove the three-layer separation works end-to-end.
   Real crypto, real Datalog evaluation, real decisions."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [stroopwafel.pdp.core :as pdp]
            [signet.chain :as chain]
            [signet.sign :as sign]
            [signet.key :as key]))

(use-fixtures :each (fn [f] (key/clear-key-store!) (f)))

;; ---------------------------------------------------------------------------
;; Basic: single chain → decision
;; ---------------------------------------------------------------------------

(deftest simple-bearer-allow
  (testing "Signed chain with matching policy → allowed"
    (let [root-kp (key/signing-keypair)
          token   (-> (chain/extend root-kp
                        {:facts [[:capability "alice" :read "/data"]]})
                      (chain/close))
          result  (-> (pdp/context)
                      (pdp/add-chain token {:trust-root (key/kid root-kp)})
                      (pdp/add-facts [[:requested-effect :read]])
                      (pdp/decide
                       :policies [{:kind :allow
                                   :query [[:capability "alice" :read "/data"]]}]))]
      (is (:allowed? result)))))

(deftest simple-bearer-deny
  (testing "Signed chain without matching capability → denied"
    (let [root-kp (key/signing-keypair)
          token   (-> (chain/extend root-kp
                        {:facts [[:capability "alice" :read "/data"]]})
                      (chain/close))
          result  (-> (pdp/context)
                      (pdp/add-chain token {:trust-root (key/kid root-kp)})
                      (pdp/add-facts [[:requested-effect :write]])
                      (pdp/decide
                       :policies [{:kind :allow
                                   :query [[:capability "alice" :write "/data"]]}]))]
      (is (not (:allowed? result))))))

;; ---------------------------------------------------------------------------
;; Untrusted root → denied
;; ---------------------------------------------------------------------------

(deftest untrusted-root-denied
  (testing "Chain signed by unknown root → errors, denied"
    (let [root-kp  (key/signing-keypair)
          other-kp (key/signing-keypair)
          token    (-> (chain/extend root-kp {:facts [[:x 1]]})
                       (chain/close))
          result   (-> (pdp/context)
                       (pdp/add-chain token {:trust-root (key/kid other-kp)})
                       (pdp/decide :policies [{:kind :allow :query [[:x 1]]}]))]
      (is (not (:allowed? result)))
      (is (seq (:errors result))))))

;; ---------------------------------------------------------------------------
;; Attenuation: delegation chain narrows access
;; ---------------------------------------------------------------------------

(deftest attenuation-narrows-access
  (testing "Attenuated chain: broad capability → narrow check"
    (let [root-kp (key/signing-keypair)
          token   (-> (chain/extend root-kp
                        {:facts [[:capability "alice" :read "/data"]
                                 [:capability "alice" :write "/data"]]})
                      ;; Attenuate: add check that only allows read
                      (chain/extend {:checks [{:id    :read-only
                                               :query [[:capability "alice" :read "/data"]]}]})
                      (chain/close))
          ;; Read should pass (capability exists + check passes)
          read-result (-> (pdp/context)
                          (pdp/add-chain token {:trust-root (key/kid root-kp)})
                          (pdp/decide
                           :policies [{:kind :allow
                                       :query [[:capability "alice" :read "/data"]]}]))]
      (is (:allowed? read-result)))))

;; ---------------------------------------------------------------------------
;; Multi-chain: facts from independent authorities combined
;; ---------------------------------------------------------------------------

(deftest multi-chain-composition
  (testing "Two chains from different authorities → facts combined"
    (let [idp-kp     (key/signing-keypair)
          service-kp (key/signing-keypair)
          ;; IdP asserts identity
          name-chain (-> (chain/extend idp-kp
                           {:facts [[:name-binding "alice-key" "ops-team"]]})
                         (chain/close))
          ;; Service grants capability to group
          cap-chain  (-> (chain/extend service-kp
                           {:facts [[:capability "ops-team" :restart "/api/service"]]})
                         (chain/close))
          ;; PDP combines both
          result (-> (pdp/context)
                     (pdp/add-chain name-chain {:trust-root (key/kid idp-kp)})
                     (pdp/add-chain cap-chain {:trust-root (key/kid service-kp)})
                     (pdp/decide
                      :rules '[{:id   :resolve-name
                                :head [:authorized ?key ?action ?resource]
                                :body [[:name-binding ?key ?name]
                                       [:capability ?name ?action ?resource]]}]
                      :policies [{:kind :allow
                                  :query [[:authorized "alice-key" :restart "/api/service"]]}]))]
      (is (:allowed? result)))))

;; ---------------------------------------------------------------------------
;; Signed envelope: requester binding
;; ---------------------------------------------------------------------------

(deftest signed-request-binding
  (testing "Agent signs request → signer kid verified → Datalog join"
    (let [root-kp  (key/signing-keypair)
          agent-kp (key/signing-keypair)
          ;; Token grants capability to this agent's kid
          token (-> (chain/extend root-kp
                      {:facts [[:authorized-agent (key/kid agent-kp)]
                               [:capability :read "/data"]]})
                    (chain/close))
          ;; Agent signs the request
          envelope (sign/sign-edn agent-kp {:method :get :path "/data"})
          ;; PDP verifies both
          result (-> (pdp/context)
                     (pdp/add-chain token {:trust-root (key/kid root-kp)})
                     (pdp/add-signed-envelope envelope)
                     (pdp/decide
                      :rules '[{:id   :agent-bound
                                :head [:agent-can-act ?kid]
                                :body [[:authorized-agent ?kid]
                                       [:request-verified-signer ?kid]]}]
                      :policies [{:kind :allow
                                  :query [[:agent-can-act '?k]
                                          [:capability :read "/data"]]}]))]
      (is (:allowed? result)))))

(deftest wrong-agent-denied
  (testing "Different agent signs → Datalog join fails → denied"
    (let [root-kp  (key/signing-keypair)
          agent-kp (key/signing-keypair)
          rogue-kp (key/signing-keypair)
          token (-> (chain/extend root-kp
                      {:facts [[:authorized-agent (key/kid agent-kp)]
                               [:capability :read "/data"]]})
                    (chain/close))
          ;; Rogue signs instead of authorized agent
          envelope (sign/sign-edn rogue-kp {:method :get :path "/data"})
          result (-> (pdp/context)
                     (pdp/add-chain token {:trust-root (key/kid root-kp)})
                     (pdp/add-signed-envelope envelope)
                     (pdp/decide
                      :rules '[{:id   :agent-bound
                                :head [:agent-can-act ?kid]
                                :body [[:authorized-agent ?kid]
                                       [:request-verified-signer ?kid]]}]
                      :policies [{:kind :allow
                                  :query [[:agent-can-act '?k]]}]))]
      (is (not (:allowed? result))))))

;; ---------------------------------------------------------------------------
;; Third-party blocks: IdP signs assertions appended to chain
;; ---------------------------------------------------------------------------

(deftest third-party-block-integration
  (testing "IdP signs name-binding → appended to chain → PDP evaluates"
    (let [root-kp (key/signing-keypair)
          idp-kp  (key/signing-keypair)
          ;; Root issues capability for ops-team
          token (chain/extend root-kp
                  {:facts [[:capability "ops-team" :restart "/api/service"]]})
          ;; IdP signs a name-binding assertion for this chain
          request  (chain/third-party-request token)
          tp-block (chain/create-third-party-block
                    request
                    {:facts [[:name-binding "alice-key" "ops-team"]]}
                    idp-kp)
          ;; Token holder appends IdP's block and seals
          token (-> (chain/extend-third-party token tp-block)
                    (chain/close))
          ;; PDP trusts both root and IdP
          result (-> (pdp/context)
                     (pdp/add-chain token {:trust-root (key/kid root-kp)})
                     (pdp/decide
                      :trusted-external-keys [(key/kid idp-kp)]
                      :rules '[{:id   :resolve
                                :head [:authorized ?key ?action ?resource]
                                :body [[:name-binding ?key ?name]
                                       [:capability ?name ?action ?resource]]}]
                      :policies [{:kind :allow
                                  :query [[:authorized "alice-key" :restart "/api/service"]]}]))]
      (is (:allowed? result)))))

;; ---------------------------------------------------------------------------
;; Tampered chain → denied
;; ---------------------------------------------------------------------------

(deftest tampered-chain-denied
  (testing "Tampered chain content → verification fails → denied"
    (let [root-kp (key/signing-keypair)
          token   (-> (chain/extend root-kp {:facts [[:capability "alice" :read "/data"]]})
                      (chain/close))
          tampered (assoc-in token [:blocks 0 :envelope :message :data]
                             {:facts [[:capability "mallory" :admin "/everything"]]})
          result  (-> (pdp/context)
                      (pdp/add-chain tampered {:trust-root (key/kid root-kp)})
                      (pdp/decide :policies [{:kind :allow :query [[:capability "mallory" :admin "/everything"]]}]))]
      (is (not (:allowed? result)))
      (is (seq (:errors result))))))

;; ---------------------------------------------------------------------------
;; Explain mode
;; ---------------------------------------------------------------------------

(deftest explain-mode
  (testing "decide with :explain? returns proof tree"
    (let [root-kp (key/signing-keypair)
          token   (-> (chain/extend root-kp {:facts [[:x 1]]})
                      (chain/close))
          result  (-> (pdp/context)
                      (pdp/add-chain token {:trust-root (key/kid root-kp)})
                      (pdp/decide
                       :explain? true
                       :checks [{:id :has-x :query [[:x 1]]}]
                       :policies [{:kind :allow :query [[:x 1]]}]))]
      (is (:allowed? result))
      (is (some? (:explain result))))))

;; ---------------------------------------------------------------------------
;; Pure facts (no chain) — local-only evaluation
;; ---------------------------------------------------------------------------

(deftest pure-facts-no-chain
  (testing "PDP works with just local facts, no signed chains"
    (let [result (-> (pdp/context)
                     (pdp/add-facts [[:capability "alice" :read "/data"]
                                     [:requested-effect :read]])
                     (pdp/decide
                      :policies [{:kind :allow
                                  :query [[:capability "alice" :read "/data"]]}]))]
      (is (:allowed? result)))))

;; ---------------------------------------------------------------------------
;; Engine limits: a limit reached is a deny with its reason, distinguishable
;; from a policy deny
;; ---------------------------------------------------------------------------

(def ^:private reach-rules
  '[{:id :r1 :head [:reach ?a ?b] :body [[:edge ?a ?b]]}
    {:id :rn :head [:reach ?a ?c] :body [[:reach ?a ?b] [:edge ?b ?c]]}])

(defn- edges [n] (mapv (fn [i] [:edge i (inc i)]) (range n)))

(deftest engine-limit-denies-with-reason
  (testing "default limits: a 50-edge closure exceeds 1000 facts"
    (let [result (-> (pdp/context)
                     (pdp/add-facts (edges 50))
                     (pdp/decide :rules reach-rules
                                 :policies [{:kind :deny :query [[:reach 0 50]]}
                                            {:kind :allow :query [[:edge 0 1]]}]))]
      (is (false? (:allowed? result)))
      (is (= :limit-exceeded (-> result :error :type)))
      (is (= :max-facts (-> result :error :limit)))))
  (testing ":limits is passed to the engine"
    (let [ctx (-> (pdp/context) (pdp/add-facts (edges 10)))
          pol [{:kind :allow :query [[:edge 0 1]]}]]
      (is (= {:allowed? true} (pdp/decide ctx :rules reach-rules :policies pol)))
      (is (= :max-facts
             (-> (pdp/decide ctx :rules reach-rules :policies pol :limits {:max-facts 30})
                 :error :limit))))))
