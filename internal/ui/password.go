package ui

import (
	"context"
	"errors"
	"strings"

	"palisade/internal/security/breach"
)

// minAdminPassword is the shortest admin password accepted (issue #273).
const minAdminPassword = 12

// ValidateAdminPassword is the one rule for every path that sets an admin
// password: invite acceptance, change password and the setup subcommand.
// The breach lookup sends only a 5-character SHA-1 prefix and fails open:
// with HIBP unreachable the length and email rules still apply. A nil
// checker skips the lookup.
func ValidateAdminPassword(ctx context.Context, hibp *breach.Checker, email, password string) error {
	if len(password) < minAdminPassword {
		return errors.New("Password must be at least 12 characters.") //nolint:staticcheck // shown to the user as is
	}
	if strings.EqualFold(strings.TrimSpace(password), strings.TrimSpace(email)) {
		return errors.New("Password must not be your email address.") //nolint:staticcheck // shown to the user as is
	}
	if hibp != nil {
		if leaked, ok := hibp.Leaked(ctx, password); ok && leaked {
			return errors.New("This password appears in a known data breach. Choose a different one.") //nolint:staticcheck // shown to the user as is
		}
	}
	return nil
}
