package main

import (
	"os"
	"testing"
)

// TestMain_version runs main itself on the one invocation that exits cleanly
// without a server; internal/app tests the rest.
func TestMain_version(t *testing.T) {
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = []string{"palisade", "--version"}
	main()
}
