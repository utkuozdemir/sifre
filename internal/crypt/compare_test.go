package crypt

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompareBidirectional(t *testing.T) {
	compareFunc := func(plaintext, hashed string) (bool, error) {
		if !strings.HasPrefix(hashed, "hash:") {
			return false, errors.New("invalid hash in tests")
		}

		return plaintext == "aaa" && hashed == "hash:aaa", nil
	}

	compare1, err := compareBidirectional("aaa", "hash:aaa", compareFunc)
	assert.NoError(t, err)
	assert.True(t, compare1)

	compare2, err := compareBidirectional("hash:aaa", "aaa", compareFunc)
	assert.NoError(t, err)
	assert.True(t, compare2)

	compare3, err := compareBidirectional("aaa", "hash:bbb", compareFunc)
	assert.NoError(t, err)
	assert.False(t, compare3)

	compare4, err := compareBidirectional("hash:bbb", "aaa", compareFunc)
	assert.NoError(t, err)
	assert.False(t, compare4)
}
