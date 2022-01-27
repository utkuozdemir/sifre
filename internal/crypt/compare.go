package crypt

import "fmt"

func compareBidirectional(str1, str2 string, compareFunc func(plaintext, hashed string) (bool, error)) (bool, error) {
	result1, err1 := compareFunc(str1, str2)
	if err1 == nil {
		return result1, nil
	}

	result2, err2 := compareFunc(str2, str1)
	if err2 == nil {
		return result2, nil
	}

	if err1 != nil && err2 != nil {
		return false, fmt.Errorf("%v, %v", err1, err2)
	}

	if err1 != nil {
		return false, err1
	}

	return false, err2
}
