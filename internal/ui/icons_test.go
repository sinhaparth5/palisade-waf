package ui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestIconsInSubset pins issue #284: the embedded hugeicons font is a subset,
// so every hgi-* name the UI uses must be in it. Run `make icons` after
// adding one.
func TestIconsInSubset(t *testing.T) {
	css, err := vendorFS.ReadFile("vendor/hugeicons/hgi-stroke-rounded.css")
	if err != nil {
		t.Fatal(err)
	}
	notIcons := map[string]bool{"hgi-stroke": true, "hgi-rounded": true, "hgi-stroke-rounded": true}
	name := regexp.MustCompile(`hgi-[a-z0-9-]+`)
	seen := 0
	for _, root := range []string{"templates", "../../static/js/src", "."} {
		err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if p != root && (root == "." || d.Name() == "vendor") {
					return filepath.SkipDir // "." means this package's Go files only
				}
				return nil
			}
			ext := filepath.Ext(p)
			if (ext != ".html" && ext != ".js" && ext != ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, n := range name.FindAllString(string(b), -1) {
				if notIcons[n] {
					continue
				}
				seen++
				if !strings.Contains(string(css), "."+n+":before{") {
					t.Errorf("%s uses %s, which isn't in the icon subset: run make icons", p, n)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if seen < 50 {
		t.Errorf("found only %d icon uses; is the walk wrong?", seen)
	}
}
