package main

import (
	handler "auth-service/internal/handlers"
	"auth-service/internal/middleware"
	"auth-service/internal/repository"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("unable to load godotenv: %v", err)
	}
	log.Println("godotenv loaded")

	repository.InitDB()
	log.Println("connected and migrated to database")

	r := gin.Default()

	r.GET("/get-tokens", handler.GetTokens)
	r.POST("/webhook", handler.Webhook)

	authGroup := r.Group("/")
	authGroup.Use(middleware.AuthMiddleware())

	authGroup.GET("/user-uuid", handler.GetUUID)
	authGroup.PUT("/refresh", handler.RefreshTokens)
	authGroup.DELETE("/deauthorize", handler.Deauthorize)

	port := os.Getenv("PORT")

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("unable to run server: %v", err)
	}
}
