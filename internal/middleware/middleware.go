package middleware

import (
	"auth-service/pkg/token"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func validateTokenPair(accessToken string, c *gin.Context) error {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		return fmt.Errorf("invalid refresh_token")
	}

	refreshTokenData, err := token.ParseJWT(refreshToken, true)
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

		err := validateTokenPair(accessToken, c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.Next()
	}
}
