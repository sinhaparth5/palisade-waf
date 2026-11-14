package ui

import "errors"

// reloadAll re-reads every runtime setting from the DB (ext.Env.Reload),
// for when the whole configuration was replaced, e.g. by cluster sync.
func (h *Handler) reloadAll() error {
	errs := []error{h.registry.Reload(h.db), h.ipbl.Reload(h.db), h.ipbl.ReloadIntel(h.db), h.geoBl.Reload(h.db)}
	rules, err := h.db.ListGeoRules()
	if err == nil && h.scorer != nil {
		h.scorer.ReloadGeoRules(rules)
	}
	enabled, threshold, ttl, berr := h.db.GetBotSettings()
	if berr == nil {
		h.reloadBot(h.buildChallenger(enabled, threshold, ttl))
	}
	h.reloadRateLimit()
	h.reloadWAF()
	for _, f := range []func(){h.reloadAutoban, h.reloadAdaptive} {
		if f != nil {
			f()
		}
	}
	return errors.Join(append(errs, err, berr)...)
}
