package store

import "errors"

var (
	// ErrCorrupt means the state file existed but could not be read as our
	// format. Load has already moved it aside; the caller cold-starts.
	ErrCorrupt = errors.New("store: state file is corrupt")

	// ErrVersion means the file was written by a newer statwatch. Reading it
	// with this version would silently drop fields on the next Save, so it is
	// fatal rather than recoverable.
	ErrVersion = errors.New("store: state file version is newer than this binary")
)
