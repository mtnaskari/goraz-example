package secrets

import (
	"errors"

	"github.com/mtnaskari/goraz/service"
	"github.com/mtnaskari/goraz/vault"
)

func isNotFound(err error) bool { return errors.Is(err, vault.ErrNotFound) }

// Unavailable reports whether err means the secrets can't be trusted right now,
// because reloads have failed for too long or the file is past its window. The
// service should then answer 503 rather than serve old data.
func Unavailable(err error) bool {
	return errors.Is(err, service.ErrStale) || errors.Is(err, service.ErrExpired)
}
