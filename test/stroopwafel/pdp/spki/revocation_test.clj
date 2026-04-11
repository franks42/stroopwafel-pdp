(ns stroopwafel.pdp.spki.revocation-test
  "Phase 5 unit tests for the revocation namespace — data model, source
   constructors, in-band collection, and the revoked? predicate.
   End-to-end revocation semantics are covered in core_test.clj."
  (:require [clojure.test :refer [deftest is testing]]
            [stroopwafel.pdp.spki.revocation :as rev]))

;; ---------------------------------------------------------------------------
;; Test-only block helpers (no signing needed — these fns are pure)
;; ---------------------------------------------------------------------------

(defn- block
  [sayer & assertions]
  {:sayer sayer :assertions (vec assertions)})

(defn- rev-assertion
  [scope target]
  {:id (random-uuid) :type :revocation :statement [scope target]})

(defn- cap-assertion
  [subject action resource]
  {:id (random-uuid) :type :capability :statement [subject action resource]})

;; ---------------------------------------------------------------------------
;; Data model
;; ---------------------------------------------------------------------------

(deftest empty-set-shape
  (is (= #{} (:ids rev/empty-set)))
  (is (= #{} (:keys rev/empty-set)))
  (is (= #{} (:subjects rev/empty-set))))

(deftest merge-sets-unions-each-scope
  (let [a {:ids #{1} :keys #{"k1"}  :subjects #{"alice"}}
        b {:ids #{2} :keys #{"k2"}  :subjects #{"bob"}}]
    (is (= {:ids #{1 2} :keys #{"k1" "k2"} :subjects #{"alice" "bob"}}
           (rev/merge-sets a b)))))

(deftest merge-sets-handles-partial-inputs
  (testing "missing scopes are treated as empty"
    (is (= {:ids #{1} :keys #{} :subjects #{}}
           (rev/merge-sets rev/empty-set {:ids #{1}})))
    (is (= {:ids #{1} :keys #{} :subjects #{}}
           (rev/merge-sets {:ids #{1}} nil)))))

;; ---------------------------------------------------------------------------
;; static-source
;; ---------------------------------------------------------------------------

(deftest static-source-returns-fixed-set
  (let [s (rev/static-source {:ids #{"id1"}})
        r (s)]
    (is (= #{"id1"} (:ids r)))
    (is (= #{} (:keys r)))
    (is (= #{} (:subjects r)))
    (is (= r (s)) "Successive calls return equal values")))

(deftest static-source-empty-default
  (let [s (rev/static-source {})]
    (is (= rev/empty-set (s)))))

;; ---------------------------------------------------------------------------
;; combine-sources
;; ---------------------------------------------------------------------------

(deftest combine-sources-merges-outputs
  (let [a        (rev/static-source {:ids #{"id1"}})
        b        (rev/static-source {:keys #{"k1"}})
        c        (rev/static-source {:subjects #{"alice"}})
        combined (rev/combine-sources a b c)
        result   (combined)]
    (is (= #{"id1"} (:ids result)))
    (is (= #{"k1"} (:keys result)))
    (is (= #{"alice"} (:subjects result)))))

(deftest combine-sources-handles-nil-returning-source
  (let [a        (rev/static-source {:ids #{"id1"}})
        nil-src  (fn [] nil)
        combined (rev/combine-sources a nil-src)]
    (is (= #{"id1"} (:ids (combined))))))

(deftest combine-sources-empty-vararg
  (let [combined (rev/combine-sources)]
    (is (= rev/empty-set (combined)))))

;; ---------------------------------------------------------------------------
;; collect-in-band
;; ---------------------------------------------------------------------------

(deftest collect-in-band-empty
  (is (= rev/empty-set (rev/collect-in-band []))))

(deftest collect-in-band-ignores-non-revocation-assertions
  (let [blocks [(block "root"
                       (cap-assertion "alice" :read "/data")
                       (cap-assertion "bob" :write "/log"))]]
    (is (= rev/empty-set (rev/collect-in-band blocks)))))

(deftest collect-in-band-all-three-scopes
  (let [target-id (random-uuid)
        blocks [(block "root"
                       (rev-assertion :assertion target-id)
                       (rev-assertion :key "bad-kid")
                       (rev-assertion :subject "mallory"))]
        r (rev/collect-in-band blocks)]
    (is (= #{target-id} (:ids r)))
    (is (= #{"bad-kid"} (:keys r)))
    (is (= #{"mallory"} (:subjects r)))))

(deftest collect-in-band-unknown-scope-silently-ignored
  (let [blocks [(block "root"
                       {:id (random-uuid)
                        :type :revocation
                        :statement [:not-a-scope "x"]})]]
    (is (= rev/empty-set (rev/collect-in-band blocks))
        "Unknown scope keywords are dropped, not errored")))

(deftest collect-in-band-across-multiple-blocks
  (let [blocks [(block "a" (rev-assertion :key "k1"))
                (block "b" (rev-assertion :key "k2"))
                (block "c" (rev-assertion :subject "alice")
                             (rev-assertion :subject "bob"))]
        r (rev/collect-in-band blocks)]
    (is (= #{"k1" "k2"} (:keys r)))
    (is (= #{"alice" "bob"} (:subjects r)))))

;; ---------------------------------------------------------------------------
;; collect-all
;; ---------------------------------------------------------------------------

(deftest collect-all-in-band-only
  (let [blocks [(block "root" (rev-assertion :key "bad-kid"))]]
    (is (= #{"bad-kid"} (:keys (rev/collect-all blocks))))))

(deftest collect-all-combines-in-band-and-source
  (let [blocks [(block "root" (rev-assertion :key "in-band-kid"))]
        source (rev/static-source {:keys #{"external-kid"}})
        r      (rev/collect-all blocks source)]
    (is (= #{"in-band-kid" "external-kid"} (:keys r)))))

(deftest collect-all-nil-source
  (let [blocks [(block "root" (rev-assertion :key "bad-kid"))]]
    (is (= #{"bad-kid"} (:keys (rev/collect-all blocks nil))))))

(deftest collect-all-source-returning-nil
  (let [blocks [(block "root" (rev-assertion :key "bad-kid"))]
        r      (rev/collect-all blocks (fn [] nil))]
    (is (= #{"bad-kid"} (:keys r))
        "A source that returns nil contributes nothing, doesn't crash")))

;; ---------------------------------------------------------------------------
;; revoked?
;; ---------------------------------------------------------------------------

(deftest revoked-by-id
  (let [id        (random-uuid)
        assertion {:id id :type :capability :statement ["alice" :read "/data"]}
        rev-set   {:ids #{id} :keys #{} :subjects #{}}]
    (is (rev/revoked? rev-set "some-sayer" assertion))))

(deftest revoked-by-key
  (let [assertion {:id (random-uuid) :type :capability
                   :statement ["alice" :read "/data"]}
        rev-set   {:ids #{} :keys #{"bad-sayer"} :subjects #{}}]
    (is (rev/revoked? rev-set "bad-sayer" assertion))
    (is (not (rev/revoked? rev-set "good-sayer" assertion)))))

(deftest revoked-by-subject
  (let [assertion {:id (random-uuid) :type :capability
                   :statement ["alice" :read "/data"]}
        rev-set   {:ids #{} :keys #{} :subjects #{"alice"}}]
    (is (rev/revoked? rev-set "sayer" assertion))))

(deftest not-revoked
  (let [assertion {:id (random-uuid) :type :capability
                   :statement ["alice" :read "/data"]}]
    (is (not (rev/revoked? rev/empty-set "sayer" assertion)))))

(deftest revoked-subject-handles-non-string-subjects
  (testing "subjects that are keywords or numbers still work — first
            element of the statement, whatever its type"
    (let [assertion {:id (random-uuid) :type :capability
                     :statement [:alice :read "/data"]}
          rev-set   {:ids #{} :keys #{} :subjects #{:alice}}]
      (is (rev/revoked? rev-set "sayer" assertion)))))

(deftest empty-statement-never-revoked-by-subject
  (let [assertion {:id (random-uuid) :type :revocation :statement []}
        rev-set   {:ids #{} :keys #{} :subjects #{nil}}]
    (is (not (rev/revoked? rev-set "sayer" assertion))
        "An assertion with an empty statement has no subject; revoking
         nil-subject should not cascade")))

;; ---------------------------------------------------------------------------
;; Composability: dynamic source backed by an atom
;; ---------------------------------------------------------------------------

(deftest dynamic-source-reflects-live-changes
  (testing "a source backed by an atom reflects changes between calls"
    (let [live   (atom {:ids #{}})
          source (fn [] @live)
          a1     {:id 1 :type :capability :statement ["alice" :read "/"]}]
      (is (not (rev/revoked? (source) "sayer" a1)))
      (swap! live update :ids conj 1)
      (is (rev/revoked? (source) "sayer" a1)))))
