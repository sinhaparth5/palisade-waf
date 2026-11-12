package services

import (
	"log"
	"strings"

	"palisade/internal/security/jwtauth"
	"palisade/internal/storage"
)

// JWTConfig converts a stored policy into the verifier's config.
func JWTConfig(j storage.ServiceJWT) jwtauth.Config {
	return jwtauth.Config{
		Mode:       j.Mode,
		JWKSURL:    j.JWKSURL,
		PublicKey:  j.PublicKey,
		Issuer:     j.Issuer,
		Audience:   j.Audience,
		Algorithms: strings.Fields(j.Algorithms),
		Prefixes:   strings.Fields(j.Prefixes),
	}
}

// loadJWTVerifiers builds each service's bearer-token check (issue #279).
// The admin UI validates a policy before saving it, so a row that no longer
// builds is only logged.
func loadJWTVerifiers(stored map[int]storage.ServiceJWT, list []storage.Service) map[string]*jwtauth.Verifier {
	out := map[string]*jwtauth.Verifier{}
	for _, s := range list {
		j, ok := stored[s.ID]
		if !ok {
			continue
		}
		v, err := jwtauth.New(JWTConfig(j))
		if err != nil {
			log.Printf("jwt: service %q: %v", s.Name, err)
			continue
		}
		out[s.Name] = v
	}
	return out
}

// JWT returns the service's bearer-token check, or nil when it has none.
func (r *Registry) JWT(name string) *jwtauth.Verifier {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.jwt[name]
}
