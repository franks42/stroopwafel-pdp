(ns stroopwafel.pdp.replay
  "Replay protection for signed requests.

   Uses UUIDv7 request-ids as both timestamp (freshness) and nonce (replay).
   Factory pattern: create-replay-guard returns an independent guard instance
   with its own cache and configurable freshness window."
  (:require [com.github.franks42.uuidv7.core :as uuidv7]))

(defn create-replay-guard
  "Create a replay guard with configurable freshness window.
   Returns {:cache (atom {}) :freshness-ms <ms>}."
  [& {:keys [freshness-ms] :or {freshness-ms 120000}}]
  {:cache        (atom {})
   :freshness-ms freshness-ms})

(defn check-freshness
  "Check that the request-id's embedded UUIDv7 timestamp is within the
   freshness window. Returns nil if OK, or error string."
  [{:keys [freshness-ms]} request-id]
  (try
    (let [uuid (if (uuid? request-id) request-id (parse-uuid (str request-id)))
          _ (when-not (uuidv7/uuidv7? uuid)
              (throw (ex-info "not UUIDv7" {})))
          ts  (uuidv7/extract-ts uuid)
          now (System/currentTimeMillis)
          age (- now ts)]
      (cond
        (> age freshness-ms)
        (str "Request too old: " age "ms (max " freshness-ms "ms)")

        (< age -5000)
        (str "Request timestamp is in the future: " (- age) "ms")

        :else nil))
    (catch Exception e
      (str "Invalid request-id: " (.getMessage e)))))

(defn check-replay
  "Check that the request-id has not been seen before.
   Returns nil if OK, or error string."
  [{:keys [cache]} request-id]
  (let [id-str (str request-id)]
    (if (contains? @cache id-str)
      "Replay detected: request-id already seen"
      (do
        (swap! cache assoc id-str (System/currentTimeMillis))
        nil))))

(defn check
  "Combined freshness + replay check.
   Returns nil if OK, or error string."
  [guard request-id]
  (or (check-freshness guard request-id)
      (check-replay guard request-id)))

(defn evict-expired!
  "Remove cache entries older than the freshness window."
  [{:keys [cache freshness-ms]}]
  (let [cutoff (- (System/currentTimeMillis) freshness-ms)]
    (swap! cache
           (fn [c]
             (into {} (filter (fn [[_ ts]] (> ts cutoff)) c))))))
