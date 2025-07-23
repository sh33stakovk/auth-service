package token

import "github.com/google/uuid"

type TokenData struct {
	TokenPairUUID uuid.UUID
	UserUUID      uuid.UUID
	UserAgent     string
	IP            string
}
