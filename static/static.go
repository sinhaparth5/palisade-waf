// Package static embeds the admin UI's built assets. It is its own package,
// not part of main, so other binaries built on palisade (palisade-pro) can
// import them.
package static

import "embed"

// JS is the theme script every admin page loads before first paint.
//
//go:embed js/*.js
var JS embed.FS

//go:embed css/dist/*
var CSS embed.FS

//go:embed imgs/*
var Imgs embed.FS

// App is the React admin app built from web/ (`make web`). static/app/dist is
// not committed; .gitkeep keeps the embed compiling before the first build.
//
//go:embed all:app
var App embed.FS
