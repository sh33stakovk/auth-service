package main

import (
	"auth-service/internal/handler"
	"auth-service/internal/middleware"
	"auth-service/internal/repository"
	"log"
	"os"

	_ "auth-service/docs"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

//	@securityDefinitions.apikey	ApiKeyAuth
//	@in							header
//	@name						Authorization
//	@description				Введите "Bearer {access_token}"

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
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

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
