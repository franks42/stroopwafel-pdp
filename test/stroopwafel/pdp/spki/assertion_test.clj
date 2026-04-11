(ns stroopwafel.pdp.spki.assertion-test
  "Phase 1 tests: construction, signing, verification, multi-assertion
   inheritance, temporal defaults. Temporal enforcement, revocation, and
   trust-closure are the pre-filter's job (Phase 2+), not tested here."
  (:require [clojure.test :refer [deftest is testing]]
            [stroopwafel.pdp.spki.assertion :as a]
            [signet.key :as key]))

;; ---------------------------------------------------------------------------
;; assertion constructor
;; ---------------------------------------------------------------------------

(deftest assertion-auto-id-test
  (testing "2-arg form auto-generates a :id"
    (let [a1 (a/assertion :capability ["alice" :read "/data"])
          a2 (a/assertion :capability ["alice" :read "/data"])]
      (is (= :capability (:type a1)))
      (is (= ["alice" :read "/data"] (:statement a1)))
      (is (some? (:id a1)))
      (is (not= (:id a1) (:id a2))
          "Two calls should produce different UUIDs"))))

(deftest assertion-explicit-id-test
  (testing "3-arg form accepts an explicit :id"
    (let [id (random-uuid)
          a  (a/assertion :name-binding id ["alice" "ops-team"])]
      (is (= id (:id a)))
      (is (= :name-binding (:type a)))
      (is (= ["alice" "ops-team"] (:statement a))))))

(deftest assertion-vector-statement-test
  (testing "statement is coerced to a vector"
    (let [a (a/assertion :capability '("alice" :read "/data"))]
      (is (vector? (:statement a)))
      (is (= ["alice" :read "/data"] (:statement a))))))

;; ---------------------------------------------------------------------------
;; sign-block + verify-block round-trip
;; ---------------------------------------------------------------------------

(def ^:private root-kp (key/signing-keypair))
(def ^:private root-kid (key/kid root-kp))

(deftest single-assertion-round-trip
  (testing "one assertion, no explicit temporal bounds"
    (let [block (a/sign-block root-kp
                              {:assertions [(a/assertion :capability
                                                         ["alice" :read "/data"])]})
          r     (a/verify-block block)]
      (is (:valid? r))
      (is (= root-kid (:sayer r)))
      (is (= 1 (count (:assertions r))))
      (is (= :capability (-> r :assertions first :type)))
      (is (= ["alice" :read "/data"] (-> r :assertions first :statement))))))

(deftest multi-assertion-round-trip
  (testing "multiple assertions in one block, all inherit sayer + temporal"
    (let [block (a/sign-block root-kp
                              {:assertions
                               [(a/assertion :capability ["alice" :read "/data"])
                                (a/assertion :name-binding ["alice" "ops-team"])
                                (a/assertion :capability ["ops-team" :restart "/api"])]})
          r     (a/verify-block block)]
      (is (:valid? r))
      (is (= root-kid (:sayer r)))
      (is (= 3 (count (:assertions r)))
          "All three assertions survive the round-trip")
      (is (= #{:capability :name-binding}
             (set (map :type (:assertions r)))))
      (testing "all assertions share the block's signing-ts and temporal bounds"
        ;; The block has one signing-ts; every assertion inherits it.
        ;; This is the whole point of block-level signing.
        (is (pos? (:signing-ts r)))
        (is (= (:signing-ts r) (:not-before r))
            ":not-before defaults to signing-ts")
        (is (nil? (:not-after r))
            ":not-after defaults to infinity (nil)")))))

;; ---------------------------------------------------------------------------
;; Temporal defaults
;; ---------------------------------------------------------------------------

(deftest not-before-defaults-to-signing-ts
  (let [before (System/currentTimeMillis)
        block  (a/sign-block root-kp
                             {:assertions [(a/assertion :capability ["a" :r "x"])]})
        after  (System/currentTimeMillis)
        r      (a/verify-block block)]
    (is (<= before (:not-before r) after)
        ":not-before is the signing-ts when not explicit")
    (is (= (:signing-ts r) (:not-before r)))))

(deftest not-before-explicit-survives
  (let [nb    1700000000000
        block (a/sign-block root-kp
                            {:not-before nb
                             :assertions [(a/assertion :capability ["a" :r "x"])]})
        r     (a/verify-block block)]
    (is (= nb (:not-before r)))
    (is (not= (:signing-ts r) (:not-before r))
        "Explicit :not-before overrides the signing-ts default")))

(deftest not-after-absent-means-infinity
  (let [block (a/sign-block root-kp
                            {:assertions [(a/assertion :capability ["a" :r "x"])]})
        r     (a/verify-block block)]
    (is (nil? (:not-after r))
        "Absent :not-after verifies as nil (no upper bound)")))

(deftest not-after-forever-means-infinity
  (let [block (a/sign-block root-kp
                            {:not-after  :forever
                             :assertions [(a/assertion :capability ["a" :r "x"])]})
        r     (a/verify-block block)]
    (is (nil? (:not-after r))
        ":forever is normalized to nil on the wire — explicit eternity")))

(deftest not-after-nil-means-infinity
  (let [block (a/sign-block root-kp
                            {:not-after  nil
                             :assertions [(a/assertion :capability ["a" :r "x"])]})
        r     (a/verify-block block)]
    (is (nil? (:not-after r))
        "Explicit nil is treated identically to :forever and absent")))

(deftest not-after-explicit-survives
  (let [na    (+ (System/currentTimeMillis) 60000)
        block (a/sign-block root-kp
                            {:not-after  na
                             :assertions [(a/assertion :capability ["a" :r "x"])]})
        r     (a/verify-block block)]
    (is (= na (:not-after r)))))

(deftest not-after-rejects-nonsense
  (is (thrown? clojure.lang.ExceptionInfo
               (a/sign-block root-kp
                             {:not-after  "not a number"
                              :assertions [(a/assertion :capability ["a" :r "x"])]}))))

;; ---------------------------------------------------------------------------
;; Different sayers → different blocks
;; ---------------------------------------------------------------------------

(deftest different-keypairs-different-sayers
  (let [kp2    (key/signing-keypair)
        block1 (a/sign-block root-kp
                             {:assertions [(a/assertion :capability ["a" :r "x"])]})
        block2 (a/sign-block kp2
                             {:assertions [(a/assertion :capability ["a" :r "x"])]})
        r1     (a/verify-block block1)
        r2     (a/verify-block block2)]
    (is (:valid? r1))
    (is (:valid? r2))
    (is (= root-kid (:sayer r1)))
    (is (= (key/kid kp2) (:sayer r2)))
    (is (not= (:sayer r1) (:sayer r2)))))

;; ---------------------------------------------------------------------------
;; Tampering
;; ---------------------------------------------------------------------------

(deftest tampered-signature-rejected
  (let [block    (a/sign-block root-kp
                               {:assertions [(a/assertion :capability ["a" :r "x"])]})
        ;; Flip one bit of the signature
        sig      ^bytes (:signature block)
        bad-sig  (byte-array (map-indexed
                              (fn [i b] (if (zero? i) (bit-flip b 0) b))
                              sig))
        tampered (assoc block :signature bad-sig)
        r        (a/verify-block tampered)]
    (is (not (:valid? r))
        "Tampered signature should not verify")))

(deftest tampered-message-rejected
  (let [block     (a/sign-block root-kp
                                {:assertions [(a/assertion :capability ["alice" :read "/data"])]})
        tampered  (assoc-in block
                            [:envelope :message :assertions 0 :statement]
                            ["mallory" :read "/data"])
        r         (a/verify-block tampered)]
    (is (not (:valid? r))
        "Message modification invalidates the signature")))

;; ---------------------------------------------------------------------------
;; Edge cases
;; ---------------------------------------------------------------------------

(deftest empty-assertions-list
  (testing "an empty block is legal (if unusual)"
    (let [block (a/sign-block root-kp {:assertions []})
          r     (a/verify-block block)]
      (is (:valid? r))
      (is (= [] (:assertions r))))))

(deftest message-digest-stable-across-signers
  (testing "two signers signing the same message produce the same :message-digest"
    (let [kp2     (key/signing-keypair)
          content {:assertions [(a/assertion :capability
                                             #uuid "00000000-0000-7000-8000-000000000001"
                                             ["alice" :read "/data"])]}
          b1      (a/sign-block root-kp content)
          b2      (a/sign-block kp2 content)
          r1      (a/verify-block b1)
          r2      (a/verify-block b2)]
      (is (java.util.Arrays/equals ^bytes (:message-digest r1)
                                   ^bytes (:message-digest r2))
          "Same message → same digest regardless of signer (quorum-friendly)")
      (is (not= (:sayer r1) (:sayer r2))))))
