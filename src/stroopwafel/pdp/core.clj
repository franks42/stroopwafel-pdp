(ns stroopwafel.pdp.core
  "Policy Decision Point — the bridge between crypto and logic.

   Verifies signed chains (signet), extracts assertions as facts,
   and feeds them to the Datalog engine (stroopwafel) for a decision.

   Usage:
     (-> (context)
         (add-chain signed-chain {:trust-root root-kid})
         (add-chain idp-chain {:trust-root idp-kid})
         (add-facts [[:current-time (System/currentTimeMillis)]
                     [:requested-effect :read]])
         (decide
           :rules [...]
           :policies [{:kind :allow :query [...]}]))
     ;; → {:allowed? true/false}"
  (:require [stroopwafel.core :as engine]
            [signet.chain :as chain]
            [signet.sign :as sign]))

(defn context
  "Create an empty PDP context.

   The context accumulates verified facts from signed chains and
   local assertions. When decide is called, all accumulated facts
   are evaluated by the Datalog engine."
  []
  {:type    :stroopwafel/pdp-context
   :blocks  []
   :facts   []
   :rules   []
   :checks  []
   :errors  []})

(defn- extract-block-content
  "Extract the data content from a verified chain block.

   Chain blocks wrap developer content in {:data <content> :next-key ... :prev-sig ...}.
   We extract :data and add :external-key if present (for third-party attribution)."
  [block-msg]
  (let [data (:data block-msg)]
    (cond-> {:facts  (or (:facts data) [])
             :rules  (or (:rules data) [])
             :checks (or (:checks data) [])}
      (:external-key block-msg)
      (assoc :external-key (:external-key block-msg)))))

(defn add-chain
  "Verify a signed chain and add its facts to the context.

   The chain is verified via signet.chain/verify. If verification
   fails, the error is recorded. If it passes, each block's
   facts, rules, and checks are extracted and added.

   Arguments:
     - ctx   : PDP context
     - token : signet chain (from signet.chain/extend + close)
     - opts  : {:trust-root <kid URN>} — expected root authority

   Returns updated context."
  [ctx token {:keys [trust-root]}]
  (let [result (chain/verify token)]
    (cond
      ;; Verification failed
      (not (:valid? result))
      (update ctx :errors conj {:reason :invalid-chain
                                :error  (:error result)})

      ;; Root doesn't match expected trust root
      (and trust-root (not= (:root token) trust-root))
      (update ctx :errors conj {:reason :untrusted-root
                                :expected trust-root
                                :actual   (:root token)})

      ;; Verified — extract blocks
      :else
      (let [block-msgs (:blocks result)
            extracted  (mapv extract-block-content block-msgs)]
        (update ctx :blocks into extracted)))))

(defn add-signed-envelope
  "Verify a signed envelope and add the signer as a fact.

   Used for requester-bound tokens where the agent signs each request.
   The verified signer's kid is added as a fact for Datalog joins.

   Arguments:
     - ctx      : PDP context
     - envelope : signet signed envelope (from signet.sign/sign-edn)

   Returns updated context with [:request-verified-signer <kid>] fact."
  [ctx envelope]
  (let [result (sign/verify-edn envelope)]
    (if (:valid? result)
      (update ctx :facts conj [:request-verified-signer (:signer result)])
      (update ctx :errors conj {:reason :invalid-signature}))))

(defn add-facts
  "Add local context facts (current time, request metadata, etc.).

   These are not signed — they represent the service's own assertions
   about the current request. Trusted because they come from the
   service itself.

   Arguments:
     - ctx   : PDP context
     - facts : vector of fact tuples

   Returns updated context."
  [ctx facts]
  (update ctx :facts into facts))

(defn add-rules
  "Add rules to the context (e.g., template rules for assertion types).

   Arguments:
     - ctx   : PDP context
     - rules : vector of rule maps

   Returns updated context."
  [ctx rules]
  (update ctx :rules into rules))

(defn decide
  "Make a policy decision based on the accumulated context.

   All verified facts from chains and local context are assembled
   into a token structure and evaluated by the stroopwafel Datalog
   engine.

   If any chain or envelope failed verification, authorization is
   denied immediately.

   Arguments:
     - ctx : PDP context
     - keyword args:
         :rules    — additional authorizer rules
         :checks   — additional authorizer checks
         :policies — ordered allow/deny policies (first match wins)
         :explain? — include proof tree in result
         :trusted-external-keys — vector of kid URNs for trusted
                                  third-party block signers
         :limits   — engine fixpoint limits (:max-iterations, :max-facts)

   Returns:
     {:allowed? boolean}
     or {:allowed? false :errors [...]}   (context errors)
     or {:allowed? false :error {:type :limit-exceeded ...}}
        (the engine reached a limit before its fixpoint)"
  [ctx & {:keys [rules checks policies explain? trusted-external-keys limits]}]
  (if (seq (:errors ctx))
    {:allowed? false :errors (:errors ctx)}
    (let [;; Merge all verified chain blocks into a single authority block.
          ;; Multi-chain composition means facts from independent chains
          ;; must be visible together in one scope. Separate blocks within
          ;; a chain (attenuation) are preserved as separate blocks.
          all-chain-facts  (into [] (mapcat :facts) (:blocks ctx))
          all-chain-rules  (into [] (mapcat :rules) (:blocks ctx))
          all-chain-checks (into [] (mapcat :checks) (:blocks ctx))
          all-ext-keys     (into [] (keep :external-key) (:blocks ctx))

          ;; Single authority block with all verified facts
          token {:blocks [(cond-> {:facts  all-chain-facts
                                   :rules  all-chain-rules
                                   :checks all-chain-checks}
                            (seq all-ext-keys)
                            (assoc :external-key (first all-ext-keys)))]}

          ;; Authorizer context: local facts + policy rules
          authorizer (cond-> {:facts    (:facts ctx)
                              :rules    (into (or (:rules ctx) []) (or rules []))
                              :checks   (into (or (:checks ctx) []) (or checks []))
                              :policies (or policies [])}
                       (seq trusted-external-keys)
                       (assoc :trusted-external-keys trusted-external-keys))

          result (engine/evaluate token
                                  :explain? explain?
                                  :authorizer authorizer
                                  :limits limits)]
      (cond-> {:allowed? (:valid? result)}
        (:error result) (assoc :error (:error result))
        explain? (assoc :explain (:explain result))))))
