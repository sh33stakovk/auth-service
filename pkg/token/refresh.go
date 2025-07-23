package token

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func GenerateRefreshToken() (uuid.UUID, string, string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return uuid.UUID{}, "", "", err
	}

	refreshToken := base64.StdEncoding.EncodeToString(randomBytes)

	refreshHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return uuid.UUID{}, "", "", err
	}

	tokPairID := uuid.New()

	return tokPairID, refreshToken, string(refreshHash), nil
}
