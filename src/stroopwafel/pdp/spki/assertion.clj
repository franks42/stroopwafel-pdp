(ns stroopwafel.pdp.spki.assertion
  "SPKI/SDSI-style assertion blocks: signed statements with mandatory
   sayer + timestamp + optional temporal bounds, as the unit of
   issuance for the assertion-based PDP.

   A block is a signet signed envelope whose message carries:
     {:not-before <epoch-ms>  — optional; absent means 'as of signing-ts'
      :not-after  <epoch-ms>  — optional; absent/nil/:forever means infinity
      :assertions [{:id :type :statement} ...]}

   All assertions in one block inherit the sayer, signing-ts, and
   temporal bounds from the envelope. Assertions needing different
   windows go in different blocks.

   The sayer is the keypair that signs the block. Trust resolution
   (primordial trust-roots + delegation closure) happens later in the
   pre-filter pipeline — this namespace only handles construction and
   signature verification.

   See docs/assertion-api-proposal.md for the full design."
  (:require [signet.sign :as sign]
            [com.github.franks42.uuidv7.core :as uuidv7]))

;; ---------------------------------------------------------------------------
;; Assertion constructor
;; ---------------------------------------------------------------------------

(defn assertion
  "Construct an assertion map.

   Arities:
     (assertion type statement)     — auto-generates a UUIDv7 :id
     (assertion type id statement)  — caller-supplied :id

   Returns: {:id <uuid> :type <keyword> :statement <vector>}

   The :type is the assertion-type keyword (:capability, :name-binding,
   :delegation, :revocation, or any custom type). The :statement is the
   type-specific positional tuple — e.g., [\"alice\" :read \"/data\"]
   for a 3-arg :capability assertion."
  ([type statement]
   (assertion type (uuidv7/uuidv7) statement))
  ([type id statement]
   {:id id :type type :statement (vec statement)}))

;; ---------------------------------------------------------------------------
;; Signing
;; ---------------------------------------------------------------------------

(defn- normalize-not-after
  "Convert :forever / nil / epoch-ms into a sign-block internal form.
   Returns nil for 'no upper bound', or an epoch-ms long."
  [v]
  (cond
    (nil? v)         nil
    (= :forever v)   nil
    (number? v)      (long v)
    :else (throw (ex-info ":not-after must be epoch-ms, :forever, or nil"
                          {:got v}))))

(defn sign-block
  "Sign a block of assertions with the given keypair.

   Options:
     :not-before  — optional epoch-ms. If absent, the block is valid as
                    of the signing timestamp (derived from signet's
                    UUIDv7 request-id). Set only when you need delayed
                    activation.
     :not-after   — optional epoch-ms, :forever, or nil. Absent/nil/
                    :forever all mean 'no upper bound'. The issuer is
                    vouching for the block indefinitely. See §5 of the
                    design doc for discussion.
     :assertions  — vector of assertion maps built via (assertion ...).

   Returns: a signet signed envelope."
  [keypair {:keys [not-before not-after assertions]}]
  (let [na      (normalize-not-after not-after)
        message (cond-> {:assertions (vec assertions)}
                  not-before (assoc :not-before (long not-before))
                  na         (assoc :not-after na))]
    (sign/sign-edn keypair message)))

;; ---------------------------------------------------------------------------
;; Verification (envelope-level only — temporal/revocation/trust are the
;; pre-filter's job)
;; ---------------------------------------------------------------------------

(defn verify-block
  "Verify the signature on a signed assertion block and unpack its
   contents into a flat result map.

   Does NOT check temporal validity, revocation, or sayer trust — those
   are handled by the pre-filter pipeline in decide.

   Returns:
     {:valid?         boolean    — signature verified
      :sayer          kid URN    — signer identity
      :signing-ts     epoch-ms   — from signet's UUIDv7 request-id
      :request-id     uuidv7     — signing event id
      :not-before     epoch-ms   — from message, or signing-ts if absent
      :not-after      epoch-ms   — from message, or nil for infinity
      :assertions     [...]      — the assertions as signed
      :message-digest bytes      — SHA-256 of canonical message
                                   (for quorum / replay use cases)}"
  [signed-block]
  (let [result (sign/verify-edn signed-block)
        msg    (:message result)
        ts     (:timestamp result)]
    {:valid?         (:valid? result)
     :sayer          (:signer result)
     :signing-ts     ts
     :request-id     (:request-id result)
     :not-before     (or (:not-before msg) ts)
     :not-after      (:not-after msg)
     :assertions     (or (:assertions msg) [])
     :message-digest (:message-digest result)}))
