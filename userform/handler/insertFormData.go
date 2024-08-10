package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github/rabinam24/userform/models"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/minio/minio-go/v7"
)

// HandleFormData handles the incoming form data and processes it.
func HandleFormData(db *sql.DB, minioClient *minio.Client, bucketName string, endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var formData models.FormData

		// Parse the incoming multipart form data
		err := r.ParseMultipartForm(10 << 20) // 10 MB limit
		if err != nil {
			log.Printf("Error parsing multipart form: %v", err)
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		// Populate formData fields from the form values
		formData.Location = r.FormValue("location")
		formData.Latitude, _ = strconv.ParseFloat(r.FormValue("latitude"), 64)
		formData.Longitude, _ = strconv.ParseFloat(r.FormValue("longitude"), 64)
		formData.SelectPole = r.FormValue("selectpole")
		formData.SelectPoleStatus = r.FormValue("selectpolestatus")
		formData.SelectPoleLocation = r.FormValue("selectpolelocation")
		formData.Description = r.FormValue("description")
		formData.AvailableISP = r.FormValue("availableisp")
		formData.SelectISP = r.FormValue("selectisp")

		// Handle single image upload for pole image
		if file, _, err := r.FormFile("poleimage"); err == nil {
			defer file.Close()

			poleImageData, err := io.ReadAll(file)
			if err != nil {
				log.Printf("Error reading single image: %v", err)
				http.Error(w, "Failed to read pole image", http.StatusInternalServerError)
				return
			}

			poleImageName := fmt.Sprintf("%d-poleimage.jpeg", time.Now().UnixNano())
			poleImageURLs, err := UploadToMinIO(minioClient, endpoint, bucketName, []string{poleImageName}, [][]byte{poleImageData})
			if err != nil {
				log.Printf("Error uploading pole image to MinIO: %v", err)
				http.Error(w, "Failed to upload pole image", http.StatusInternalServerError)
				return
			}

			formData.PoleImage = poleImageURLs[0]
			log.Println("Uploaded Pole Image:", poleImageURLs[0])
		} else if err != http.ErrMissingFile {
			log.Printf("Error handling pole image: %v", err)
			http.Error(w, "Failed to handle pole image", http.StatusInternalServerError)
			return
		} else {
			formData.PoleImage = "" // Set to empty if no image provided
		}

		// Handle multiple images upload
		multipleImageFiles := r.MultipartForm.File["multipleimages"]
		var multipleImageURLs []string

		for i, fileHeader := range multipleImageFiles {
			file, err := fileHeader.Open()
			if err != nil {
				log.Printf("Error opening multiple image %d: %v", i, err)
				http.Error(w, fmt.Sprintf("Failed to open image %d", i), http.StatusInternalServerError)
				return
			}

			imageData, err := io.ReadAll(file)
			file.Close()
			if err != nil {
				log.Printf("Error reading multiple image %d: %v", i, err)
				http.Error(w, fmt.Sprintf("Failed to read image %d", i), http.StatusInternalServerError)
				return
			}

			imageName := fmt.Sprintf("%d-multipleimage-%d.jpeg", time.Now().UnixNano(), i)
			imageURLs, err := UploadToMinIO(minioClient, endpoint, bucketName, []string{imageName}, [][]byte{imageData})
			if err != nil {
				log.Printf("Error uploading multiple image %d to MinIO: %v", i, err)
				http.Error(w, fmt.Sprintf("Failed to upload image %d", i), http.StatusInternalServerError)
				return
			}

			multipleImageURLs = append(multipleImageURLs, imageURLs...)
		}

		formData.MultipleImages = multipleImageURLs
		log.Println("Uploaded multiple images:", multipleImageURLs)

		// Insert form data into the database
		if err := InsertData(db, formData); err != nil {
			log.Printf("Error inserting data into database: %v", err)
			http.Error(w, "Failed to insert data into database", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Data inserted successfully"))
	}
}

// InsertData inserts the form data into the database.
func InsertData(db *sql.DB, formData models.FormData) error {
	multipleImagesJSON, err := json.Marshal(formData.MultipleImages)
	if err != nil {
		return fmt.Errorf("failed to marshal image URLs to JSON: %w", err)
	}

	query := `
        INSERT INTO userform (
			location, latitude, longitude, selectpole, 
			selectpolestatus, selectpolelocation, description, 
			poleimage, availableisp, selectisp, multipleimages, created_at
		) 
		VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		);`

	log.Println("Attempting to insert data into the database.")
	_, err = db.Exec(query,
		formData.Location,
		formData.Latitude,
		formData.Longitude,
		formData.SelectPole,
		formData.SelectPoleStatus,
		formData.SelectPoleLocation,
		formData.Description,
		sql.NullString{String: formData.PoleImage, Valid: formData.PoleImage != ""}, // Handle nullable PoleImage
		formData.AvailableISP,
		formData.SelectISP,
		string(multipleImagesJSON),
		time.Now(),
	)

	if err != nil {
		log.Printf("Error executing SQL query: %v", err)
		return fmt.Errorf("failed to insert data into database: %w", err)
	}

	log.Println("Data inserted successfully.")
	return nil
}
