(ns stroopwafel.pdp.replay-test
  (:require [clojure.test :refer [deftest is]]
            [stroopwafel.pdp.replay :as replay]
            [com.github.franks42.uuidv7.core :as uuidv7]))

(deftest fresh-request-passes
  (let [guard (replay/create-replay-guard)
        rid   (uuidv7/uuidv7)]
    (is (nil? (replay/check guard rid)))))

(deftest replay-rejected
  (let [guard (replay/create-replay-guard)
        rid   (uuidv7/uuidv7)]
    (is (nil? (replay/check guard rid)))
    (is (some? (replay/check guard rid)))))

(deftest two-different-ids-pass
  (let [guard (replay/create-replay-guard)
        rid1  (uuidv7/uuidv7)
        rid2  (uuidv7/uuidv7)]
    (is (nil? (replay/check guard rid1)))
    (is (nil? (replay/check guard rid2)))))

(deftest eviction-removes-old
  (let [guard (replay/create-replay-guard :freshness-ms 50)
        rid   (uuidv7/uuidv7)]
    (replay/check-replay guard rid)
    (is (= 1 (count @(:cache guard))))
    (Thread/sleep 60)
    (replay/evict-expired! guard)
    (is (= 0 (count @(:cache guard))))))
