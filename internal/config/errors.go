package config

import "errors"

// ErrInvalid wraps every validation failure. The message names the YAML key
// so an operator can fix the file without reading this package.
var ErrInvalid = errors.New("config: invalid")
