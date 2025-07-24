package handler

import (
	"auth-service/internal/model"
	"auth-service/internal/repository"
	"auth-service/pkg/token"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func createTokenPair(tokenData token.TokenData, c *gin.Context) {
	refreshToken, err := token.GenerateJWT(tokenData, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	accessToken, err := token.GenerateJWT(tokenData, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	err = repository.DB.Create(&model.RefreshToken{
		TokenPairUUID:    tokenData.TokenPairUUID,
		RefreshTokenHash: string(refreshTokenHash),
	}).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.SetCookie(
		"refresh_token",
		refreshToken,
		7*24*60*60,
		"/",
		"",
		false,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
	})
}

func GetTokens(c *gin.Context) {
	userUUIDStr := c.Query("user_uuid")
	userUUID, err := uuid.Parse(userUUIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_uuid"})
		return
	}

	tokenPairUUID := uuid.New()
	userAgent := c.Request.UserAgent()
	ip := c.ClientIP()

	tokenData := token.TokenData{
		TokenPairUUID: tokenPairUUID,
		UserUUID:      userUUID,
		UserAgent:     userAgent,
		IP:            ip,
	}

	createTokenPair(tokenData, c)
}

func GetUUID(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing access token"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	tokenData, err := token.ParseJWT(tokenString, false)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_uuid": tokenData.UserUUID,
	})
}

func sendWebhook(url string, payload any) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook error: %v - %s", resp.Status, string(body))
	}

	return nil
}

func RefreshTokens(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing refresh_token"})
		return
	}

	tokenData, err := token.ParseJWT(refreshToken, true)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var refreshTokenHash string
	err = repository.DB.Model(&model.RefreshToken{}).
		Where("token_pair_uuid = ?", tokenData.TokenPairUUID).
		Select("refresh_token_hash").
		Scan(&refreshTokenHash).
		Error
	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh_token"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(refreshTokenHash), []byte(refreshToken))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh_token"})
		return
	}

	reqUserAgent := c.Request.UserAgent()
	reqIP := c.ClientIP()

	if tokenData.UserAgent != reqUserAgent {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_agent was changed"})
		return
	}

	if tokenData.IP != reqIP {
		payload := map[string]string{
			"user_uuid": tokenData.UserUUID.String(),
			"old_ip":    tokenData.IP,
			"new_ip":    reqIP,
			"message":   "ip changed",
		}

		err = sendWebhook("http://localhost:8081/webhook", payload)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	err = repository.DeleteToken(tokenData.TokenPairUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	newTokenData := token.TokenData{
		TokenPairUUID: uuid.New(),
		UserUUID:      tokenData.UserUUID,
		UserAgent:     reqUserAgent,
		IP:            reqIP,
	}

	createTokenPair(newTokenData, c)
}
