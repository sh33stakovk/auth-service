package main

import (
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
	log.Println("connected to database")

	r := gin.Default()

	port := os.Getenv("PORT")

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("unable to run server: %v", err)
	}
}
