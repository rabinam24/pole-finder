package handler

import (
	"database/sql"
	"encoding/json"
	"github/rabinam24/userform/models"
	"log"
	"math"
	"net/http"
	"time"
)

func HandleTotalDistances(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := `SELECT id, latitude, longitude, created_at::date AS date
		          FROM userform
		          WHERE created_at >= Now() - INTERVAL '7 days'
		          ORDER BY date`

		rows, err := db.Query(query)
		if err != nil {
			log.Printf("Error while querying the data: %v", err)
			http.Error(w, "Error while querying the data", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type DailyDistance struct {
			Date     string   `json:"date"`
			Distance *float64 `json:"distance"`
		}

		dailyDistances := make(map[string]float64)
		var previousData *models.GPSData

		for rows.Next() {
			var gpsData models.GPSData
			err := rows.Scan(&gpsData.ID, &gpsData.Latitude, &gpsData.Longitude, &gpsData.Date)
			if err != nil {
				log.Printf("Error scanning rows: %v", err)
				http.Error(w, "Error scanning rows", http.StatusInternalServerError)
				return
			}

			dateStr := gpsData.Date.Format("2006-01-02")
			if previousData != nil && previousData.Date.Format("2006-01-02") == dateStr {
				dailyDistances[dateStr] += CalculateDistance(previousData.Latitude, previousData.Longitude, gpsData.Latitude, gpsData.Longitude)
			}
			previousData = &gpsData
		}

		if err := rows.Err(); err != nil {
			log.Printf("Error iterating over rows: %v", err)
			http.Error(w, "Error iterating over rows", http.StatusInternalServerError)
			return
		}

		// Prepare the response for the last 7 days
		response := make([]DailyDistance, 7)
		for i := 0; i < 7; i++ {
			date := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
			if distance, found := dailyDistances[date]; found {
				response[6-i] = DailyDistance{Date: date, Distance: &distance}
			} else {
				response[6-i] = DailyDistance{Date: date, Distance: nil}
			}
		}

		// Convert the response to JSON
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshalling JSON: %v", err)
			http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
			return
		}

		// Set content-type header and write response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(jsonResponse)
	}
}

func CalculateDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const EarthRadius = 6371 // Earth's radius in kilometers

	// Convert latitude and longitude from degrees to radians
	lat1 = lat1 * math.Pi / 180
	lat2 = lat2 * math.Pi / 180
	lon1 = lon1 * math.Pi / 180
	lon2 = lon2 * math.Pi / 180

	// Haversine formula
	deltaLat := lat2 - lat1
	deltaLon := lon2 - lon1

	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1)*math.Cos(lat2)*math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return (EarthRadius * c)
}
