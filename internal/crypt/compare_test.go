package crypt_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/utkuozdemir/sifre/internal/crypt"
)

func TestCompareBidirectional(t *testing.T) {
	t.Parallel()

	compareFunc := func(plaintext, hashed string) (bool, error) {
		if !strings.HasPrefix(hashed, "hash:") {
			return false, crypt.ErrInvalidHash
		}

		return plaintext == "aaa" && hashed == "hash:aaa", nil
	}

	compare1, err := crypt.CompareBidirectional("aaa", "hash:aaa", compareFunc)
	assert.NoError(t, err)
	assert.True(t, compare1)

	compare2, err := crypt.CompareBidirectional("hash:aaa", "aaa", compareFunc)
	assert.NoError(t, err)
	assert.True(t, compare2)

	compare3, err := crypt.CompareBidirectional("aaa", "hash:bbb", compareFunc)
	assert.NoError(t, err)
	assert.False(t, compare3)

	compare4, err := crypt.CompareBidirectional("hash:bbb", "aaa", compareFunc)
	assert.NoError(t, err)
	assert.False(t, compare4)
}
