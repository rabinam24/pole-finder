package handler

import (
	"database/sql"
	"encoding/json"
	"github/rabinam24/userform/models"
	"log"
	"net/http"
	"strconv"
)

func HandleUserData(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("Fetching user data...")

		rows, err := db.Query("SELECT id, location, latitude, longitude, selectpole, selectpolestatus, selectpolelocation, description, poleimage, availableisp, selectisp, multipleimages, created_at FROM userform")
		if err != nil {
			log.Printf("Error querying database: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var data []models.FormData
		for rows.Next() {
			var formData models.FormData
			var poleImageJSON, multipleImagesJSON sql.NullString

			err := rows.Scan(
				&formData.ID,
				&formData.Location,
				&formData.Latitude,
				&formData.Longitude,
				&formData.SelectPole,
				&formData.SelectPoleStatus,
				&formData.SelectPoleLocation,
				&formData.Description,
				&poleImageJSON,
				&formData.AvailableISP,
				&formData.SelectISP,
				&multipleImagesJSON,
				&formData.CreatedAt,
			)
			if err != nil {
				log.Printf("Error scanning row: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Handle NULL values for poleImage
			if poleImageJSON.Valid {
				formData.PoleImage = poleImageJSON.String
			}

			// Handle NULL values for multipleImages
			if multipleImagesJSON.Valid && multipleImagesJSON.String != "" {
				if err := json.Unmarshal([]byte(multipleImagesJSON.String), &formData.MultipleImages); err != nil {
					log.Printf("Error unmarshalling JSON: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			}

			data = append(data, formData)
		}

		if err := rows.Err(); err != nil {
			log.Printf("Row iteration error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(data); err != nil {
			log.Printf("Error encoding JSON response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}

func HandleUserDataParticular(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "Missing username parameter", http.StatusBadRequest)
			return
		}

		log.Printf("Fetching the user details for the particular user: %s", username)

		query := `
        SELECT uf.id, uf.location, uf.latitude, uf.longitude, uf.selectpole, uf.selectpolestatus, 
               uf.selectpolelocation, uf.description, uf.poleimage, uf.availableisp, uf.selectisp, 
               uf.multipleimages, uf.created_at 
        FROM userform uf
        JOIN users u ON uf.user_id = u.id
        WHERE u.username = $1
        `

		rows, err := db.Query(query, username)
		if err != nil {
			log.Printf("Error querying the database for particular users: %v", err)
			http.Error(w, "Error querying the database", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var data []models.FormData
		for rows.Next() {
			var formData models.FormData
			var poleImageJSON, multipleImagesJSON sql.NullString

			err := rows.Scan(
				&formData.ID,
				&formData.Location,
				&formData.Latitude,
				&formData.Longitude,
				&formData.SelectPole,
				&formData.SelectPoleStatus,
				&formData.SelectPoleLocation,
				&formData.Description,
				&poleImageJSON,
				&formData.AvailableISP,
				&formData.SelectISP,
				&multipleImagesJSON,
				&formData.CreatedAt,
			)
			if err != nil {
				log.Printf("Error scanning row: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Handle NULL values for poleImage
			if poleImageJSON.Valid {
				formData.PoleImage = poleImageJSON.String
			}

			// Handle NULL values for multipleImages
			if multipleImagesJSON.Valid && multipleImagesJSON.String != "" {
				if err := json.Unmarshal([]byte(multipleImagesJSON.String), &formData.MultipleImages); err != nil {
					log.Printf("Error unmarshalling JSON: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			}

			data = append(data, formData)
		}

		if err := rows.Err(); err != nil {
			log.Printf("Row iteration error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(data); err != nil {
			log.Printf("Error encoding JSON response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}

func IsInvalidFloat(value float64) bool {
	return value != value
}

func HandleDeleteData(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.URL.Path[len("/api/data/"):]
		id, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "Invalid ID", http.StatusBadRequest)
			return
		}

		query := "DELETE FROM userform WHERE id = $1"
		_, err = db.Exec(query, id)
		if err != nil {
			log.Printf("Error deleting data: %v", err)
			http.Error(w, "Failed to delete data", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Data deleted successfully"))
	}
}
