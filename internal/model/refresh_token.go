package model

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// В БД хранится уникальный идентификатор пары access и refresh токенов и хэш refresh токена
type RefreshToken struct {
	gorm.Model
	TokenPairUUID    uuid.UUID `gorm:"type:uuid;not null;unique"`
	RefreshTokenHash string    `gorm:"not null"`
}
