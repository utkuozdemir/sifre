package crypt

import (
	"errors"
	"fmt"

	bc "golang.org/x/crypto/bcrypt"
)

type bcryptGenerator struct {
	cost int
}

type bcryptComparer struct {
	cost int
}

func NewBcryptGenerator(cost int) (Generator, error) {
	if cost < bc.MinCost || cost > bc.MaxCost {
		return nil, fmt.Errorf("invalid clist: %d, must be between %d and %d",
			cost, bc.MinCost, bc.MaxCost)
	}

	return &bcryptGenerator{cost: cost}, nil
}

func NewBcryptComparer() (BidirectionalComparer, error) {
	return &bcryptComparer{}, nil
}

func (b *bcryptGenerator) Generate(plaintext string) (string, error) {
	password, err := bc.GenerateFromPassword([]byte(plaintext), b.cost)
	if err != nil {
		return "", err
	}

	return string(password), nil
}

func (b *bcryptComparer) Compare(plaintext, hashed string) (bool, error) {
	err := bc.CompareHashAndPassword([]byte(hashed), []byte(plaintext))
	if err == nil {
		return true, nil
	}

	if errors.Is(err, bc.ErrMismatchedHashAndPassword) {
		return false, nil
	}

	return false, err
}

func (b *bcryptComparer) CompareBidirectional(plaintext, hashed string) (bool, error) {
	return compareBidirectional(plaintext, hashed, b.Compare)
}
