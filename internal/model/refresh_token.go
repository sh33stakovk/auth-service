package model

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RefreshToken struct {
	gorm.Model
	TokenPairUUID    uuid.UUID `gorm:"type:uuid;not null;unique"`
	RefreshTokenHash string    `gorm:"not null"`
}
