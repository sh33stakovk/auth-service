package model

import (
	"github.com/google/uuid"
)

type RefreshToken struct {
	TokenPairUUID    uuid.UUID `gorm:"type:uuid;not null;unique"`
	RefreshTokenHash string    `gorm:"not null"`
}
