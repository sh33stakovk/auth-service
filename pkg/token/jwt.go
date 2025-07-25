package token

import (
	"auth-service/internal/repository"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func getJWTSecretAndExpiry(isRefresh bool) (secretKey []byte, expiresAt int64) {
	if isRefresh {
		return []byte(os.Getenv("REFRESH")), time.Now().Add(time.Hour * 24 * 7).Unix()
	} else {
		return []byte(os.Getenv("ACCESS")), time.Now().Add(time.Minute * 15).Unix()
	}
}

/*
Функция для генерации access и refresh токенов
Время жизни access токена 15 минут, а refresh токена - 7 дней
Оба токена в формате base64, так как это дефолтный формат JWT
*/
func GenerateJWT(tokenData TokenData, isRefresh bool) (string, error) {
	secretKey, expiresAt := getJWTSecretAndExpiry(isRefresh)

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"jti":        tokenData.TokenPairUUID.String(),
		"user_uuid":  tokenData.UserUUID.String(),
		"user_agent": tokenData.UserAgent,
		"ip":         tokenData.IP,
		"exp":        expiresAt,
	})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Функция для сбора данных токена в структуру TokenData
func getTokenData(claims jwt.MapClaims) (TokenData, error) {
	var tokenData TokenData
	var err error

	jti, ok := claims["jti"].(string)
	if !ok {
		return TokenData{}, fmt.Errorf("cannot get jti")
	}

	tokenData.TokenPairUUID, err = uuid.Parse(jti)
	if err != nil {
		return TokenData{}, err
	}

	userUUID, ok := claims["user_uuid"].(string)
	if !ok {
		return TokenData{}, fmt.Errorf("cannot get user_uuid")
	}

	tokenData.UserUUID, err = uuid.Parse(userUUID)
	if err != nil {
		return TokenData{}, err
	}

	tokenData.UserAgent, ok = claims["user_agent"].(string)
	if !ok {
		return TokenData{}, fmt.Errorf("cannot get user_agent")
	}

	tokenData.IP, ok = claims["ip"].(string)
	if !ok {
		return TokenData{}, fmt.Errorf("cannot get ip")
	}

	return tokenData, nil
}

/*
Функция для парса токенов
Если refresh токен просрочен, то он автоматически удаляется из БД. В случае access токена просто возвращается ошибка
*/
func ParseJWT(tokenString string, isRefresh bool) (TokenData, error) {
	var tokenData TokenData

	secretKey, _ := getJWTSecretAndExpiry(isRefresh)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unknown signing method")
		}

		return secretKey, nil
	})

	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return TokenData{}, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		tokenData, err = getTokenData(claims)
		if err != nil {
			return TokenData{}, err
		}
	}

	if errors.Is(err, jwt.ErrTokenExpired) {
		if isRefresh {
			err = repository.DeleteToken(tokenData.TokenPairUUID)
			if err != nil {
				return TokenData{}, err
			}
		}

		return TokenData{}, err
	}

	if !token.Valid {
		return TokenData{}, fmt.Errorf("invalid token")
	}

	return tokenData, nil
}

// Функция для перевода токена в SHA256 перед хэшированием в bcrypt, так как bcrypt не поддерживает длину JWT токенов
func hashTokenSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Функция хэширования токена
func HashToken(token string) ([]byte, error) {
	shaToken := hashTokenSHA256(token)
	return bcrypt.GenerateFromPassword([]byte(shaToken), bcrypt.DefaultCost)
}

// Функция сравнения хэша с токеном
func CompareToken(hashed []byte, token string) error {
	shaToken := hashTokenSHA256(token)
	return bcrypt.CompareHashAndPassword(hashed, []byte(shaToken))
}
