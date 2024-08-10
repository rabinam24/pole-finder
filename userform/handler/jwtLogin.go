package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github/rabinam24/userform/models"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func HandleUserSignup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userData models.User
		if err := json.NewDecoder(r.Body).Decode(&userData); err != nil {
			log.Printf("Error decoding the json data: %v", err)
			http.Error(w, "Error decoding the json data", http.StatusInternalServerError)
			return
		}
		if db != nil {
			if err := HandleInsertUserDetails(db, &userData); err != nil {
				log.Printf("Error inserting the data into the database:%v", err)
				http.Error(w, "Error inserting the data into the database", http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Data inserted Sucessfully"))

	}
}

func GenerateJWT(username string, secretKey string, ttl time.Duration) (string, error) {
	claims := models.TokenClaims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ttl).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func HandleUserLogin(db *sql.DB, cfg models.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.User
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding the request body: %v", err)
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		query := "SELECT password FROM users WHERE username = $1"
		var storedPassword string
		err := db.QueryRow(query, req.Username).Scan(&storedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("Username is not registered in the database: %v", req.Email)
				http.Error(w, "Username not registered", http.StatusUnauthorized)
				return
			}
			log.Printf("Error querying database: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if !CheckPasswordHash(req.Password, storedPassword) {
			log.Printf("Password does not match for email: %v", req.Email)
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		accessToken, err := GenerateJWT(req.Username, cfg.Jwt.SecretKey, cfg.Jwt.AccessTokenTTL)
		if err != nil {
			log.Printf("Error generating access token: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		refreshToken, err := GenerateJWT(req.Username, cfg.Jwt.SecretKey, cfg.Jwt.RefreshTokenTTL)
		if err != nil {
			log.Printf("Error generating refresh token: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := models.AuthResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		w.Write([]byte("Login successfully done"))
	}
}

func HandleRefreshToken(cfg models.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.AuthResponse
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding the request body: %v", err)
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		claims := &models.TokenClaims{}
		_, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.Jwt.SecretKey), nil
		})
		if err != nil {
			log.Printf("Invalid refresh token: %v", err)
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}

		newAccessToken, err := GenerateJWT(claims.Username, cfg.Jwt.SecretKey, cfg.Jwt.AccessTokenTTL)
		if err != nil {
			log.Printf("Error generating new access token: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := models.AuthResponse{
			AccessToken: newAccessToken,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func HandlePasswordChanger(db *sql.DB, cfg models.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.PasswordChanger
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding the json request:%v", err)
			http.Error(w, "Error decoding the json request", http.StatusInternalServerError)
			return
		}

		query := `SELECT password FROM users WHERE username= $1`
		var storedPassword string
		err := db.QueryRow(query, req.Username).Scan(&storedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("Email is not registered in the database:%v", req.Username)
				http.Error(w, "Email is not registered in the database", http.StatusInternalServerError)
				return
			}
			log.Printf("Error querying the database:%v", err)
			http.Error(w, "Error querying the database", http.StatusInternalServerError)
			return

		}
		if !CheckPasswordHash(req.OldPassword, storedPassword) {
			log.Printf("Password does not match for the email:%v", req.Username)
			http.Error(w, "Password Invalid", http.StatusInternalServerError)
			return
		}

		hashedPassword, err := HashPassword(req.NewPassword)
		if err != nil {
			log.Printf("Error hashing the new password:%v", err)
			http.Error(w, "Error hashing the new Password", http.StatusInternalServerError)
			return
		}
		UpdateQuery := `UPDATE users SET password = $1 WHERE username = $2`
		_, err = db.Exec(UpdateQuery, hashedPassword, req.Username)
		if err != nil {
			log.Printf("Error updating password in the database: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Password updated successfully")

	}
}
