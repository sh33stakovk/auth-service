package middleware

import (
	"auth-service/internal/repository"
	"auth-service/pkg/token"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func validateAndGetTokenPair(accessToken string, c *gin.Context) error {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		return fmt.Errorf("invalid refresh_token")
	}

	refreshTokenData, err := token.ParseJWT(refreshToken, true)
	if err != nil {
		return fmt.Errorf("invalid refresh_token")
	}

	var refreshTokenHash string
	err = repository.DB.Where("token_pair_uuid = ?", refreshTokenData.TokenPairUUID).
		Select("refresh_token_hash").
		Scan(&refreshTokenHash).
		Error
	if err == gorm.ErrRecordNotFound {
		return fmt.Errorf("invalid refresh_token")
	} else if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(refreshTokenHash), []byte(refreshToken))
	if err != nil {
		return fmt.Errorf("invalid refresh_token")
	}

	accessTokenData, err := token.ParseJWT(accessToken, false)
	if err != nil {
		return fmt.Errorf("invalid access_token")
	}

	if accessTokenData.TokenPairUUID != refreshTokenData.TokenPairUUID {
		return fmt.Errorf("invalid access_token")
	}

	c.Set("refresh_token_data", refreshTokenData)
	c.Set("access_token_data", accessTokenData)

	return nil
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing access_token"})
			return
		}

		accessToken := strings.TrimPrefix(authHeader, "Bearer ")

		err := validateAndGetTokenPair(accessToken, c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.Set("access_token", accessToken)

		c.Next()
	}
}
