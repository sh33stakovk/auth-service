package token

import (
	"auth-service/internal/repository"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	refreshSecret = []byte(os.Getenv("REFRESH"))
	accessSecret  = []byte(os.Getenv("ACCESS"))
)

func getJWTSecretAndExpiry(isRefresh bool) (secretKey []byte, expiresAt int64) {
	if isRefresh {
		return refreshSecret, time.Now().Add(time.Hour * 24 * 7).Unix()
	} else {
		return accessSecret, time.Now().Add(time.Minute * 15).Unix()
	}
}

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

		return TokenData{}, fmt.Errorf("token expired")
	}

	if !token.Valid {
		return TokenData{}, fmt.Errorf("invalid token")
	}

	return tokenData, nil
}
