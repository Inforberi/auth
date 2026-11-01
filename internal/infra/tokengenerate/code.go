package tokengenerate

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func (TokenManager) GenerateCode() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08d", value.Int64()), nil
}
