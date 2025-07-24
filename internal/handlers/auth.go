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
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var webhookURL = os.Getenv("WEBHOOK_URL")

type WebhookPayload struct {
	UserUUID string `json:"user_uuid"`
	OldIP    string `json:"old_ip"`
	NewIP    string `json:"new_ip"`
	Message  string `json:"message"`
}

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

	refreshTokenHash, err := token.HashToken(refreshToken)
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

func getTokenData(key string, c *gin.Context) (token.TokenData, error) {
	contextData, exists := c.Get(key)
	if !exists {
		return token.TokenData{}, fmt.Errorf("missing token data")
	}

	tokenData, ok := contextData.(token.TokenData)
	if !ok {
		return token.TokenData{}, fmt.Errorf("cannot get access token data")
	}

	return tokenData, nil
}

func GetUUID(c *gin.Context) {
	accessTokenData, err := getTokenData("access_token_data", c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_uuid": accessTokenData.UserUUID,
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing refresh_token"})
		return
	}

	refreshTokenData, err := token.ParseJWT(refreshToken, true)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh_token"})
		return
	}

	var refreshTokenHash string
	err = repository.DB.Model(&model.RefreshToken{}).
		Where("token_pair_uuid = ?", refreshTokenData.TokenPairUUID).
		Select("refresh_token_hash").
		Scan(&refreshTokenHash).
		Error
	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh_token"})
		return
	} else if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	err = token.CompareToken([]byte(refreshTokenHash), refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh_token"})
		return
	}

	accessTokenData, err := getTokenData("access_token_data", c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if accessTokenData.TokenPairUUID != refreshTokenData.TokenPairUUID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid acces_token"})
		return
	}

	reqUserAgent := c.Request.UserAgent()
	reqIP := c.ClientIP()

	if refreshTokenData.UserAgent != reqUserAgent {
		err = repository.DeleteToken(refreshTokenData.TokenPairUUID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_agent was changed"})
		return
	}

	if refreshTokenData.IP != reqIP {
		payload := WebhookPayload{
			UserUUID: refreshTokenData.UserUUID.String(),
			OldIP:    refreshTokenData.IP,
			NewIP:    reqIP,
			Message:  "ip changed",
		}

		err = sendWebhook(webhookURL, payload)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	err = repository.DeleteToken(refreshTokenData.TokenPairUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	newTokenData := token.TokenData{
		TokenPairUUID: uuid.New(),
		UserUUID:      refreshTokenData.UserUUID,
		UserAgent:     reqUserAgent,
		IP:            reqIP,
	}

	createTokenPair(newTokenData, c)
}

func Deauthorize(c *gin.Context) {
	accessTokenData, err := getTokenData("access_token_data", c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	err = repository.DeleteToken(accessTokenData.TokenPairUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "deauthorized"})
}

func Webhook(c *gin.Context) {
	var payload WebhookPayload

	err := c.ShouldBindJSON(&payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "received"})
}
