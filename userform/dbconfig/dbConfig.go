package dbconfig

import (
	"database/sql"
	"fmt"
	"github/rabinam24/userform/models"
)

func ConnectDB(cfg models.Config) (*sql.DB, error) {
	// Additional debug statement for DSN
	fmt.Println("Connecting to database with DSN:", cfg.Db.Dsn)
	db, err := sql.Open("postgres", cfg.Db.Dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}
