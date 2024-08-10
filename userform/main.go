package main

import (
	"flag"
	"fmt"
	"github/rabinam24/userform/dbconfig"
	"github/rabinam24/userform/models"
	"github/rabinam24/userform/routes"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
)

func main() {

	// Configuration for database connection
	var cfg models.Config
	flag.StringVar(&cfg.Db.Dsn, "dsn", "", "Postgres connection string")
	flag.StringVar(&cfg.Jwt.SecretKey, "jwt-secret", "your-secret-key", "JWT Secret Key")
	flag.DurationVar(&cfg.Jwt.AccessTokenTTL, "access-token-ttl", 15*time.Minute, "Access Token TTL")
	flag.DurationVar(&cfg.Jwt.RefreshTokenTTL, "refresh-token-ttl", 7*24*time.Hour, "Refresh Token TTL")
	flag.Parse()

	if cfg.Db.Dsn == "" {
		host := os.Getenv("DB_HOST")
		port := os.Getenv("DB_PORT")
		user := os.Getenv("DB_USER")
		password := os.Getenv("DB_PASSWORD")
		dbname := os.Getenv("DB_NAME")

		cfg.Db.Dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	}

	// Connect to the database
	db, err := dbconfig.ConnectDB(cfg)
	if err != nil {
		log.Fatal("Error connecting to the database:", err)
	}
	defer db.Close()

	// Set up routes
	mux := routes.SetupRoutes(db)

	// Start the server
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal("Error starting server:", err)
	}
}
