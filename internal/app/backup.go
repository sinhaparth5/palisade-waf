package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"palisade/internal/storage"
)

// runBackup writes a consistent copy of the DB with VACUUM INTO, safe while
// the server runs (issue #329). It never migrates the DB, so the Helm chart
// can run it from the new image before the new version first opens the file.
// --out writes one file and fails if the DB is missing. --dir writes
// <name>-<UTC time>.db, keeps the newest --keep of them, and treats a missing
// DB as a fresh install with nothing to back up.
// Invoked as: palisade backup [--db path] (--out file | --dir dir [--keep n])
func runBackup(args []string, stdout io.Writer) error {
	fl := flag.NewFlagSet("backup", flag.ContinueOnError)
	dbPath, dbDriver := dbFlags(fl)
	out := fl.String("out", "", "write the backup to this file (must not exist)")
	dir := fl.String("dir", "", "write a timestamped backup into this directory")
	keep := fl.Int("keep", 5, "with --dir: backups of this DB to keep, oldest removed first (0 = all)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if (*out == "") == (*dir == "") {
		return errors.New("pass exactly one of --out or --dir")
	}
	if err := checkSQLite(*dbDriver, *dbPath); err != nil {
		return err
	}
	// Opening a missing file would create an empty DB, so look first.
	if _, err := os.Stat(*dbPath); err != nil {
		if *dir != "" && errors.Is(err, fs.ErrNotExist) {
			_, err = fmt.Fprintf(stdout, "no database at %s, nothing to back up\n", *dbPath)
			return err
		}
		return err
	}

	dst := *out
	prefix := strings.TrimSuffix(filepath.Base(*dbPath), filepath.Ext(*dbPath)) + "-"
	if *dir != "" {
		if err := os.MkdirAll(*dir, 0o700); err != nil {
			return err
		}
		dst = filepath.Join(*dir, prefix+time.Now().UTC().Format("20060102T150405Z")+".db")
	}
	if err := storage.BackupFile(*dbPath, dst); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, "backup written to", dst); err != nil {
		return err
	}
	if *dir == "" || *keep <= 0 {
		return nil
	}
	// The timestamp sorts lexically, so the oldest come first.
	old, err := filepath.Glob(filepath.Join(*dir, prefix+"*.db"))
	if err != nil {
		return err
	}
	sort.Strings(old)
	for len(old) > *keep {
		if err := os.Remove(old[0]); err != nil {
			return err
		}
		old = old[1:]
	}
	return nil
}
