// Package ext lets a binary built on palisade (palisade-pro) add admin routes
// and Settings cards. The open-source binary registers nothing.
package ext

import (
	"html/template"

	"github.com/labstack/echo/v5"

	"palisade/internal/storage"
)

// Env is what a feature gets when the admin UI mounts it.
type Env struct {
	DB        *storage.DB
	AdminPath string
}

// Route is an admin route under the admin path, behind the session, CSRF,
// audit log and Role (storage.RoleViewer/Admin/Owner; required).
type Route struct {
	Method, Path, Role string
	Handler            echo.HandlerFunc
}

// Card renders a Settings card for the signed-in user's role; "" hides it.
type Card func(c *echo.Context, role string) template.HTML

// Feature is one mounted add-on.
type Feature struct {
	Routes []Route
	Card   Card
}

// Mounts are called once per admin UI, from init functions appending here.
var Mounts []func(Env) Feature
