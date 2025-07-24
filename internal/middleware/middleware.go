package middleware

import (
	"auth-service/pkg/token"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing access_token"})
			return
		}

		accessToken := strings.TrimPrefix(authHeader, "Bearer ")

		accessTokenData, err := token.ParseJWT(accessToken, false)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid access_token"})
			return
		}

		c.Set("access_token_data", accessTokenData)

		c.Next()
	}
}
