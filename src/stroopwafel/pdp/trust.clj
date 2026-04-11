(ns stroopwafel.pdp.trust
  "Trust-root fact generation for Datalog authorization.

   Converts trust-root configurations into [:trusted-root kid effect domain]
   facts using kid URNs as key identifiers.")

(defn trust-root-facts
  "Convert trust-roots config into Datalog facts.

   Accepts either:
   - A single kid URN string (unscoped — trust for everything)
   - A map of {kid → {:scoped-to {:effects #{...} :domains #{...}}}}
   - nil → []

   Returns vector of [:trusted-root kid effect domain] facts."
  [trust-roots]
  (cond
    ;; Single kid — trust for everything
    (string? trust-roots)
    [[:trusted-root trust-roots :any :any]]

    ;; Map of kid → scope
    (map? trust-roots)
    (into []
          (mapcat (fn [[kid {:keys [scoped-to]}]]
                    (if scoped-to
                      (for [effect (:effects scoped-to)
                            domain (:domains scoped-to)]
                        [:trusted-root kid effect domain])
                      [[:trusted-root kid :any :any]])))
          trust-roots)

    :else []))
