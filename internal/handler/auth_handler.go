package handler

import (
	"auth-service/internal/model"
	"auth-service/internal/repository"
	"auth-service/pkg/swagger"
	"auth-service/pkg/token"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func createTokenPair(tokenData token.TokenData, c *gin.Context) error {
	refreshToken, err := token.GenerateJWT(tokenData, true)
	if err != nil {
		return err
	}

	accessToken, err := token.GenerateJWT(tokenData, false)
	if err != nil {
		return err
	}

	refreshTokenHash, err := token.HashToken(refreshToken)
	if err != nil {
		return err
	}

	err = repository.DB.Create(&model.RefreshToken{
		TokenPairUUID:    tokenData.TokenPairUUID,
		RefreshTokenHash: string(refreshTokenHash),
	}).Error
	if err != nil {
		return err
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

	return nil
}

// @Summary		Получение access и refresh токенов
// @Description	Возвращает access токен в теле ответа, refresh токен устанавливается в cookie и сохраняется в БД в bcrypt-хэше.
// @Produce		json
// @Param			user_uuid	query		string						true	"UUID пользователя"	default(619899ea-6aa3-44b9-9a8c-e8a68799ea09)
// @Success		200			{object}	swagger.AccessTokenSuccess	"access_token успешно возвращён"
// @Failure		400			{object}	swagger.GetTokensFailure400	"некорректный UUID пользователя"
// @Failure		401			{object}	swagger.GetTokensFailure401	"ошибка генерации или сохранения токенов"
// @Router			/get-tokens [get]
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

	if err = createTokenPair(tokenData, c); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
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

// @Summary		Получение UUID пользователя
// @Description	Возвращается UUID пользователя, который берется из данных access токена.
// @Produce		json
// @Security		ApiKeyAuth
// @Success		200	{object}	swagger.GetUUIDSuccess		"UUID пользователя успешно возвращён"
// @Failure		401	{object}	swagger.AccessTokenFailure	"отсутствуют или некорректны данные access токена"
// @Router			/user-uuid [get]
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

// @Summary		Обновление пары токенов
// @Description	Получает access токен из Authorization: Bearer и refresh токен из cookie. При успехе возвращает новый access токен и устанавливает новый refresh токен в cookie, записывая хэш в БД и удаляя старый. Токены должны быть из одной пары. При смене User-Agent происходит деавторизация, а при смене IP отсылается уведомление на webhook.
// @Produce		json
// @Security		ApiKeyAuth
// @Success		200	{object}	swagger.AccessTokenSuccess	"новый access токен успешно возвращён и refresh токен обновлён"
// @Failure		401	{object}	swagger.AccessTokenFailure	"отсутствует или неверен refresh/access токен, User-Agent изменён, или ошибка сравнения токенов"
// @Failure		500	{object}	swagger.TokenDataFailure	"ошибки при удалении токена или получении данных из контекста"
// @Router			/refresh [put]
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access_token"})
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
		payload := swagger.WebhookPayload{
			UserUUID: refreshTokenData.UserUUID.String(),
			OldIP:    refreshTokenData.IP,
			NewIP:    reqIP,
			Message:  "ip changed",
		}

		err = sendWebhook(os.Getenv("WEBHOOK_URL"), payload)
		if err != nil {
			log.Printf("webhook error: %v", err)
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

	if err = createTokenPair(newTokenData, c); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
}

// @Summary		Деавторизация
// @Description	Удаляет refresh токен из БД по TokenPairUUID, полученному из access токена (access токен невалиден при отсутствии refresh токена с таким же TokenPairUUID в БД).
// @Produce		json
// @Security		ApiKeyAuth
// @Success		200	{object}	swagger.DeauthorizeSuccess	"успешная деавторизация"
// @Failure		401	{object}	swagger.AccessTokenFailure	"неверный access токен"
// @Failure		500	{object}	swagger.TokenDataFailure	"ошибка получения данных токена или удаления токена из БД"
// @Router			/deauthorize [delete]
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

// @Summary	Вебхук для уведомлений о смене IP
// @Accept		json
// @Produce	json
// @Param		payload	body		swagger.WebhookPayload	true	"Данные вебхука"
// @Success	200		{object}	swagger.WebhookSuccess	"уведомление успешно принято"
// @Failure	400		{object}	swagger.WebhookFailure	"ошибка при разборе данных JSON"
// @Router		/webhook [post]
func Webhook(c *gin.Context) {
	var payload swagger.WebhookPayload

	err := c.ShouldBindJSON(&payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "received"})
}
