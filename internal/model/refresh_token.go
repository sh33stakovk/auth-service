package model

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RefreshToken struct {
	gorm.Model
	UserID    uuid.UUID `gorm:"type:uuid;not null"`
	TokenHash string    `gorm:"type:varchar(60);not null"`
	UserAgent string    `gorm:"type:text;not null"`
	IP        string    `gorm:"type:inet;not null"`
	Expired   bool      `gorm:"default:false"`
}
