package models

import "time"

type Config struct {
	Db struct {
		Dsn string
	}
	Jwt struct {
		SecretKey       string
		AccessTokenTTL  time.Duration
		RefreshTokenTTL time.Duration
	}
}
