package services

import (
	"palisade/internal/security/bot"
	"palisade/internal/storage"
)

// AIAction is the AI crawler policy action (issue #187) for category cat on
// app: the service's override, else the global default. "" means no policy.
// Nil-receiver safe; app may be nil (unmatched traffic gets the default).
func (r *Registry) AIAction(app *storage.Service, cat string) string {
	if r == nil {
		return ""
	}
	if app != nil {
		if a := bot.ParseAIPolicy(app.AICrawlerPolicy)[cat]; a != "" {
			return a
		}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.aiDefault[cat]
}
