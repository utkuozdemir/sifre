package crypt

import (
	"errors"
	"fmt"

	bc "golang.org/x/crypto/bcrypt"
)

type BcryptGenerator struct {
	cost int
}

type BcryptComparer struct{}

func NewBcryptGenerator(cost int) (*BcryptGenerator, error) {
	if cost < bc.MinCost || cost > bc.MaxCost {
		return nil, fmt.Errorf("invalid cost: %d, must be between %d and %d",
			cost, bc.MinCost, bc.MaxCost)
	}

	return &BcryptGenerator{cost: cost}, nil
}

func NewBcryptComparer() (*BcryptComparer, error) {
	return &BcryptComparer{}, nil
}

func (b *BcryptGenerator) Generate(plaintext string) (string, error) {
	password, err := bc.GenerateFromPassword([]byte(plaintext), b.cost)
	if err != nil {
		return "", err
	}

	return string(password), nil
}

func (b *BcryptComparer) Compare(plaintext, hashed string) (bool, error) {
	err := bc.CompareHashAndPassword([]byte(hashed), []byte(plaintext))
	if err == nil {
		return true, nil
	}

	if errors.Is(err, bc.ErrMismatchedHashAndPassword) {
		return false, nil
	}

	return false, err
}

func (b *BcryptComparer) CompareBidirectional(plaintext, hashed string) (bool, error) {
	return CompareBidirectional(plaintext, hashed, b.Compare)
}
