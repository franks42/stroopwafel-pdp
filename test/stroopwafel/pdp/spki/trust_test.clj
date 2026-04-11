(ns stroopwafel.pdp.spki.trust-test
  "Phase 3 unit tests for trust.clj — the trust closure + delegation
   fixpoint. Integration tests that exercise the closure end-to-end
   through the pre-filter live in core_test.clj."
  (:require [clojure.test :refer [deftest is testing]]
            [stroopwafel.pdp.spki.trust :as trust]))

;; ---------------------------------------------------------------------------
;; Fake blocks — we construct trust inputs directly, no signing needed.
;; Each block is a map with :sayer and :assertions (and optionally :not-after).
;; ---------------------------------------------------------------------------

(defn- block
  [sayer & {:keys [not-after assertions]}]
  {:sayer      sayer
   :not-after  not-after
   :assertions (or assertions [])})

(defn- delegation
  ([delegate] (delegation delegate :all))
  ([delegate type]
   {:id (random-uuid) :type :delegation :statement [delegate type]}))

(def ^:private ^:const now 1000000)

;; ---------------------------------------------------------------------------
;; Primordial only (no delegation)
;; ---------------------------------------------------------------------------

(deftest primordial-set-becomes-all-trust
  (let [entries (trust/resolve #{"A" "B"} [] now 0)]
    (is (= 2 (count entries)))
    (is (every? #(= :all (:for-types %)) entries))
    (is (every? #(nil? (:not-after %)) entries))
    (is (trust/trusted-for? entries "A" :capability now 0))
    (is (trust/trusted-for? entries "B" :name-binding now 0))
    (is (not (trust/trusted-for? entries "C" :capability now 0)))))

(deftest primordial-map-scoped
  (let [entries (trust/resolve {"A" {:for-types #{:capability}}
                                "B" {:for-types :all :not-after 2000000}}
                               [] now 0)]
    (is (trust/trusted-for? entries "A" :capability now 0))
    (is (not (trust/trusted-for? entries "A" :name-binding now 0)))
    (is (trust/trusted-for? entries "B" :capability now 0))
    ;; B expires at 2000000; at now=3000000 it's no longer trusted
    (is (not (trust/trusted-for? entries "B" :capability 3000000 0)))))

;; ---------------------------------------------------------------------------
;; One-hop delegation
;; ---------------------------------------------------------------------------

(deftest single-hop-delegation-full
  (testing "A primordial, A delegates :all to B → B trusted for :all"
    (let [blocks  [(block "A" :assertions [(delegation "B" :all)])]
          entries (trust/resolve #{"A"} blocks now 0)]
      (is (trust/trusted-for? entries "B" :capability now 0))
      (is (trust/trusted-for? entries "B" :name-binding now 0)))))

(deftest single-hop-delegation-typed
  (testing "A primordial, A delegates :capability to B → B trusted only for :capability"
    (let [blocks  [(block "A" :assertions [(delegation "B" :capability)])]
          entries (trust/resolve #{"A"} blocks now 0)]
      (is (trust/trusted-for? entries "B" :capability now 0))
      (is (not (trust/trusted-for? entries "B" :name-binding now 0))))))

(deftest delegation-narrows-scoped-delegator
  (testing "A primordial for #{:capability}, A delegates :all to B → B gets :capability only"
    (let [blocks  [(block "A" :assertions [(delegation "B" :all)])]
          entries (trust/resolve {"A" {:for-types #{:capability}}}
                                 blocks now 0)]
      (is (trust/trusted-for? entries "B" :capability now 0))
      (is (not (trust/trusted-for? entries "B" :name-binding now 0))))))

(deftest delegation-out-of-scope-rejected
  (testing "A primordial for #{:capability}, A delegates :name-binding to B → no effect"
    (let [blocks  [(block "A" :assertions [(delegation "B" :name-binding)])]
          entries (trust/resolve {"A" {:for-types #{:capability}}}
                                 blocks now 0)]
      (is (not (trust/trusted-for? entries "B" :name-binding now 0)))
      (is (not (trust/trusted-for? entries "B" :capability now 0))))))

;; ---------------------------------------------------------------------------
;; Multi-hop delegation
;; ---------------------------------------------------------------------------

(deftest two-hop-delegation
  (testing "A → B → C all :all"
    (let [blocks  [(block "A" :assertions [(delegation "B" :all)])
                   (block "B" :assertions [(delegation "C" :all)])]
          entries (trust/resolve #{"A"} blocks now 0)]
      (is (trust/trusted-for? entries "A" :capability now 0))
      (is (trust/trusted-for? entries "B" :capability now 0))
      (is (trust/trusted-for? entries "C" :capability now 0)))))

(deftest three-hop-delegation-narrowing
  (testing "A(:all) → B(:capability) → C(:all) → C ends up with :capability only"
    (let [blocks  [(block "A" :assertions [(delegation "B" :capability)])
                   (block "B" :assertions [(delegation "C" :all)])]
          entries (trust/resolve #{"A"} blocks now 0)]
      (is (trust/trusted-for? entries "C" :capability now 0))
      (is (not (trust/trusted-for? entries "C" :name-binding now 0))))))

;; ---------------------------------------------------------------------------
;; Temporal attenuation
;; ---------------------------------------------------------------------------

(deftest delegation-not-after-caps-delegate
  (testing "Delegator :not-after nil, delegation block :not-after 5000 → C capped at 5000"
    (let [blocks  [(block "A" :not-after 5000
                          :assertions [(delegation "B" :all)])]
          entries (trust/resolve #{"A"} blocks now 0)
          b-entry (some #(when (= (:kid %) "B") %) entries)]
      (is (= 5000 (:not-after b-entry))))))

(deftest delegator-not-after-floors-delegate
  (testing "Delegator :not-after 3000, delegation block :not-after 5000 → C capped at 3000"
    ;; Use a small 'now' so A's primordial (expiring at 3000) is still active
    (let [blocks  [(block "A" :not-after 5000
                          :assertions [(delegation "B" :all)])]
          entries (trust/resolve {"A" {:for-types :all :not-after 3000}}
                                 blocks 1000 0)
          b-entry (some #(when (and (= (:kid %) "B") (= :delegated (:origin %))) %)
                        entries)]
      (is (= 3000 (:not-after b-entry))))))

(deftest delegate-check-respects-window
  (let [blocks  [(block "A" :not-after 5000
                        :assertions [(delegation "B" :all)])]
        entries (trust/resolve #{"A"} blocks now 0)]
    (is (trust/trusted-for? entries "B" :capability 4000 0))   ; inside window
    (is (not (trust/trusted-for? entries "B" :capability 6000 0))) ; past window
    (is (trust/trusted-for? entries "B" :capability 5500 1000) ; with skew
        "Clock skew of 1000 ms extends effective validity")))

;; ---------------------------------------------------------------------------
;; Primordial + delegation overlap (pinned decision §11 #6: widen)
;; ---------------------------------------------------------------------------

(deftest primordial-is-a-floor-delegation-widens
  (testing "B is primordial for #{:capability}; A delegates :name-binding to B.
            B's effective scope should cover BOTH :capability and :name-binding
            (union, not intersection)."
    (let [blocks  [(block "A" :assertions [(delegation "B" :name-binding)])]
          entries (trust/resolve {"A" {:for-types :all}
                                  "B" {:for-types #{:capability}}}
                                 blocks now 0)]
      (is (trust/trusted-for? entries "B" :capability now 0)
          "B keeps the primordial :capability trust")
      (is (trust/trusted-for? entries "B" :name-binding now 0)
          "B also picks up :name-binding via delegation from A"))))

;; ---------------------------------------------------------------------------
;; Untrusted-delegator and cycle handling
;; ---------------------------------------------------------------------------

(deftest untrusted-delegator-ignored
  (testing "X is not a primordial root; X delegating to B has no effect"
    (let [blocks  [(block "X" :assertions [(delegation "B" :all)])]
          entries (trust/resolve #{"A"} blocks now 0)]
      (is (not (trust/trusted-for? entries "B" :capability now 0))))))

(deftest cycle-converges
  (testing "A → B → A should not loop forever"
    (let [blocks  [(block "A" :assertions [(delegation "B" :all)])
                   (block "B" :assertions [(delegation "A" :all)])]
          entries (trust/resolve #{"A"} blocks now 0)]
      (is (trust/trusted-for? entries "A" :capability now 0))
      (is (trust/trusted-for? entries "B" :capability now 0)))))

(deftest multi-delegator-to-same-delegate
  (testing "A delegates :capability to C; B delegates :name-binding to C.
            C should be trusted for both (OR-semantics)."
    (let [blocks  [(block "A" :assertions [(delegation "C" :capability)])
                   (block "B" :assertions [(delegation "C" :name-binding)])]
          entries (trust/resolve #{"A" "B"} blocks now 0)]
      (is (trust/trusted-for? entries "C" :capability now 0))
      (is (trust/trusted-for? entries "C" :name-binding now 0))
      (is (not (trust/trusted-for? entries "C" :revocation now 0))))))
