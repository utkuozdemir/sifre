package crypt

type BidirectionalComparer interface {
	Comparer
	CompareBidirectional(str1, str2 string) (bool, error)
}

type Generator interface {
	Generate(plaintext string) (string, error)
}

type Algorithm interface {
	Generator
	BidirectionalComparer
}

type Comparer interface {
	Compare(plaintext, hashed string) (bool, error)
}
