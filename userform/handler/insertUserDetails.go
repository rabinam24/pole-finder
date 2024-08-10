package handler

import (
	"database/sql"
	"github/rabinam24/userform/models"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}
func HandleInsertUserDetails(db *sql.DB, user *models.User) error {
	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		return err
	}
	query := `INSERT INTO users (username, email, phone , password ) VALUES ($1,$2,$3,$4)`
	_, err = db.Exec(query, user.Username, user.Email, user.Phone, hashedPassword)
	if err != nil {
		return err
	}
	return nil

}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
