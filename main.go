// Regenerates static/js/dist/*.min.js from static/js/src/*.js before build.
// `make build` runs this automatically; if running `go build` directly,
// run `go generate ./...` first after editing any source JS file.
//go:generate go run ./tools/minify

package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"palisade/internal/app"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	// The first SIGINT/SIGTERM starts a graceful shutdown; a second one kills.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	context.AfterFunc(ctx, stop)
	err := app.Run(ctx, os.Args[1:], version, app.Assets{JS: staticJS, CSS: staticCSS, Imgs: staticImgs}, os.Stdin, os.Stdout)
	stop()
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}
