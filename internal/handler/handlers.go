package handler

import (
	"auth-service/internal/model"
	"auth-service/internal/repository"
	"auth-service/pkg/token"
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func GetTokens(c *gin.Context) {
	userIDStr := c.Query("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	tokPairID, refreshToken, refreshHash, err := token.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	accessToken, err := token.GenerateAccessToken(tokPairID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	err = repository.DB.Create(&model.RefreshToken{
		UserID:           userID,
		RefreshTokenHash: refreshHash,
		UserAgent:        c.Request.UserAgent(),
		IP:               c.ClientIP(),
		TokenPairID:      tokPairID,
	}).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_pair_id": tokPairID.String(),
	})
}

func RefreshTokens(c *gin.Context) {
	req := struct {
		UserID       string `json:"user_id"`
		RefreshToken string `refresh_token:"refresh_token"`
	}{}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	reqUserID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing access token"})
		return
	}

	reqUserAgent := c.GetHeader("User-Agent")
	reqIP := c.ClientIP()

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	tokPairID, accUserID, err := token.ParseAccessToken(accessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if accUserID != reqUserID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "wrong access or refresh token"})
		return
	}

	prevParams := struct {
		UserAgent string
		IP        string
	}{}

	err = repository.DB.Where("user_id = ? AND token_hash = ? AND token_pair_id = ? AND expired = ?", req.UserID, req.RefreshToken, tokPairID, false).
		Select("user_agent", "ip").
		Scan(&prevParams).
		Error
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if prevParams.UserAgent != reqUserAgent {
		err = repository.DB.Where("user_id = ? AND token_hash = ? AND expired = ?", req.UserID, req.RefreshToken, false).
			Update("expired", true).
			Error
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.JSON(
			http.StatusUnauthorized,
			gin.H{"message": "user-agent was changed, the user has been deauthorized"},
		)
		return
	}

	if prevParams.IP != reqIP {
		payload := map[string]interface{}{
			"user_id": req.UserID,
			"old_ip":  prevParams.IP,
			"new_ip":  reqIP,
			"message": "ip was changed",
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		resp, err := http.Post(
			"http://localhost:8081/webhook",
			"application/json",
			bytes.NewBuffer(jsonData),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer resp.Body.Close()
	}

	newRefreshToken, newRefreshHash, err := token.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	newAccessToken, err := token.GenerateAccessToken(reqUserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	newSession := model.RefreshToken{
		UserID:    reqUserID,
		TokenHash: newRefreshHash,
		UserAgent: reqUserAgent,
		IP:        reqIP,
		Expired:   false,
	}

	err = repository.DB.Create(&newSession).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":           "tokens refreshred",
		"user_id":           reqUserID,
		"new_access_token":  newAccessToken,
		"new_refresh_token": newRefreshToken,
	})
}

func GetUUID(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing access token"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	res, err := token.ParseAccessToken(tokenString)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id": res,
	})
}
