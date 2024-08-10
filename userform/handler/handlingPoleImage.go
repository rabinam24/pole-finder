package handler

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
)

func HandleUserPoleImage(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := `SELECT poleimage, multipleimages FROM userform`
		row := db.QueryRow(query)

		var poleImage string
		var multipleImagesJSON sql.NullString

		err := row.Scan(&poleImage, &multipleImagesJSON)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("No rows found: %v", err)
				http.Error(w, "No images found", http.StatusNotFound)
				return
			}
			log.Printf("Error querying the database: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"poleImage": poleImage,
		}

		if multipleImagesJSON.Valid && multipleImagesJSON.String != "" {
			var multipleImages []string
			if err := json.Unmarshal([]byte(multipleImagesJSON.String), &multipleImages); err != nil {
				log.Printf("Error unmarshalling JSON: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			response["multipleImages"] = multipleImages
		} else {
			response["multipleImages"] = []string{}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
