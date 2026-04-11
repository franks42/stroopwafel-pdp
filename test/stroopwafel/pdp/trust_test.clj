(ns stroopwafel.pdp.trust-test
  (:require [clojure.test :refer [deftest is]]
            [stroopwafel.pdp.trust :as trust]))

(deftest single-kid-produces-unscoped-fact
  (let [facts (trust/trust-root-facts "urn:signet:pk:Ed25519:abc123")]
    (is (= 1 (count facts)))
    (is (= [:trusted-root "urn:signet:pk:Ed25519:abc123" :any :any]
           (first facts)))))

(deftest multi-root-map-produces-scoped-facts
  (let [facts (trust/trust-root-facts
               {"urn:signet:pk:Ed25519:abc" {:scoped-to {:effects #{:read :write}
                                                          :domains #{"market" "account"}}}})]
    (is (= 4 (count facts)))
    (is (every? #(= :trusted-root (first %)) facts))))

(deftest unscoped-entry-in-map
  (let [facts (trust/trust-root-facts {"urn:signet:pk:Ed25519:abc" {}})]
    (is (= 1 (count facts)))
    (is (= [:trusted-root "urn:signet:pk:Ed25519:abc" :any :any] (first facts)))))

(deftest nil-produces-empty
  (is (= [] (trust/trust-root-facts nil))))
