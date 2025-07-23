package repository

import (
	"auth-service/internal/model"
	"log"
	"os"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	conStr := "host=" + os.Getenv("DB_HOST") +
		" user=" + os.Getenv("DB_USER") +
		" password=" + os.Getenv("DB_PASS") +
		" dbname=" + os.Getenv("DB_NAME") +
		" port=" + os.Getenv("DB_PORT") +
		" sslmode=disable"

	var err error
	DB, err = gorm.Open(postgres.Open(conStr))
	if err != nil {
		log.Fatalf("unable to connect to database: %v", err.Error())
	}
}

func DeleteToken(tokenPairUUID uuid.UUID) error {
	return DB.Where("token_pair_uuid = ?", tokenPairUUID).Delete(&model.RefreshToken{}).Error
}
