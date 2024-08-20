package routes

import (
	"database/sql"
	"github/rabinam24/userform/handler"
	"github/rabinam24/userform/models"
	"log"
	"net/http"
	"os"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func SetupRoutes(db *sql.DB) http.Handler {
	mux := http.NewServeMux()

	endpoint := os.Getenv("MINIO_ENDPOINT")
	accessKeyID := os.Getenv("MINIO_ACCESS_KEY")
	secretAccessKey := os.Getenv("MINIO_SECRET_KEY")
	useSSL := os.Getenv("MINIO_SSL") == "true"

	if endpoint == "" {
		log.Fatalln("MINIO_ENDPOINT is not set or empty")
	}

	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL,
	})

	if err != nil {
		log.Fatalln("Failed to initialize MinIO client:", err)
	}

	var cfg models.Config

	bucketName := "location-tracker"
	mux.HandleFunc("/submit-form", handler.HandleFormData(db, minioClient, bucketName, endpoint))

	mux.HandleFunc("/user-data", handler.HandleUserData(db))
	mux.HandleFunc("/user-datas", handler.HandleUserDataParticular(db))

	mux.HandleFunc("/api/data/{id}", handler.HandleDeleteData(db))
	mux.HandleFunc("/save-user", handler.SaveUser(db))

	mux.HandleFunc("/api/gps-data", handler.HandlegetGpsData(db))
	mux.HandleFunc("/api/pole-image", handler.HandleUserPoleImage(db))
	mux.HandleFunc("/start_trip", handler.HandleStartTrip(db))
	mux.HandleFunc("/end_trip", handler.HandleEndTrip(db))
	mux.HandleFunc("/get_trip_state", handler.HandleGetTripState(db))
	mux.HandleFunc("/total-distances", handler.HandleTotalDistances(db))
	mux.HandleFunc("/sign-up", handler.HandleUserSignup(db))
	mux.HandleFunc("/login", handler.HandleUserLogin(db, cfg))
	mux.HandleFunc("/refresh-token", handler.HandleRefreshToken(cfg))
	mux.HandleFunc("/password-changer", handler.HandlePasswordChanger(db, cfg))
	mux.HandleFunc("/logins", handler.Login)
	mux.HandleFunc("/calling", handler.HandleCallback)
	mux.HandleFunc("/logout", handler.Logout)
	mux.HandleFunc("/secret", handler.Secret)
	mux.HandleFunc("/oauth/token", handler.ProxyOAuthToken)
	mux.HandleFunc("/get_user_info", handler.GetUserInfo)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handler.CorsMiddleware(http.DefaultServeMux).ServeHTTP(w, r)
	})

	return handler.CorsMiddleware(mux)
}
