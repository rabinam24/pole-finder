package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github/rabinam24/userform/models"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

func GetTripData(db *sql.DB, username string) (*models.StartEnd, error) {
	query := "SELECT username, trip_started, trip_start_time, trip_end_time, original_trip_start_time FROM trip WHERE username = $1 ORDER BY id DESC LIMIT 1"
	row := db.QueryRow(query, username)

	var trip models.StartEnd
	err := row.Scan(&trip.Username, &trip.TripStarted, &trip.TripStartTime, &trip.TripEndTime, &trip.OriginalTripStartTime)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to retrieve trip data: %w", err)
	}

	return &trip, nil
}

func UpsertTripData(db *sql.DB, startEnd *models.StartEnd) error {
	query := `
        INSERT INTO trip (username, trip_started, trip_start_time, trip_end_time, original_trip_start_time)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (username)
        DO UPDATE SET trip_started = EXCLUDED.trip_started, trip_start_time = EXCLUDED.trip_start_time, trip_end_time = EXCLUDED.trip_end_time, original_trip_start_time = EXCLUDED.original_trip_start_time
    `

	_, err := db.Exec(query, startEnd.Username, startEnd.TripStarted, startEnd.TripStartTime, startEnd.TripEndTime, startEnd.OriginalTripStartTime)
	if err != nil {
		return fmt.Errorf("failed to insert or update trip data: %w", err)
	}

	return nil
}

func HandleStartTrip(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		var requestBody struct {
			Username string `json:"username"`
		}
		err = json.Unmarshal(body, &requestBody)
		if err != nil {
			http.Error(w, "Failed to parse request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		username := requestBody.Username
		if username == "" {
			http.Error(w, "Username is missing in request body", http.StatusBadRequest)
			return
		}

		existingTrip, err := GetTripData(db, username)
		if err != nil {
			http.Error(w, "Failed to retrieve trip data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if existingTrip != nil && existingTrip.TripStarted {
			log.Printf("Conflict: Trip already started for username %s", username)
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte("Trip is already started"))
			return
		}

		tripStartTime := time.Now()
		var originalTripStartTime time.Time
		if existingTrip != nil && existingTrip.OriginalTripStartTime != nil {
			originalTripStartTime = *existingTrip.OriginalTripStartTime
		} else {
			originalTripStartTime = tripStartTime
		}

		startEnd := models.StartEnd{
			Username:              username,
			TripStarted:           true,
			TripStartTime:         &tripStartTime,
			TripEndTime:           nil,
			OriginalTripStartTime: &originalTripStartTime,
		}

		err = UpsertTripData(db, &startEnd)
		if err != nil {
			http.Error(w, "Failed to insert or update trip data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Trip started successfully for username %s at %v", username, tripStartTime)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Trip started successfully"))
	}
}

func HandleEndTrip(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		var requestBody struct {
			Username string `json:"username"`
		}
		err = json.Unmarshal(body, &requestBody)
		if err != nil {
			http.Error(w, "Failed to parse request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		username := requestBody.Username
		if username == "" {
			http.Error(w, "Username is missing in request body", http.StatusBadRequest)
			return
		}

		existingTrip, err := GetTripData(db, username)
		if err != nil {
			http.Error(w, "Failed to retrieve trip data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if existingTrip == nil || !existingTrip.TripStarted {
			http.Error(w, "No trip in progress", http.StatusConflict)
			return
		}

		tripEndTime := time.Now()

		startEnd := models.StartEnd{
			Username:              username,
			TripStarted:           false,
			TripStartTime:         existingTrip.TripStartTime,
			TripEndTime:           &tripEndTime,
			OriginalTripStartTime: existingTrip.OriginalTripStartTime,
		}

		err = UpsertTripData(db, &startEnd)
		if err != nil {
			http.Error(w, "Failed to update trip data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		activeTripsMutex.Lock()
		delete(activeTrips, username)
		activeTripsMutex.Unlock()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Trip ended successfully"))
	}
}

var (
	activeTripsMutex sync.Mutex
	activeTrips      = make(map[string]*time.Time)
)

func HandleGetTripState(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var requestBody struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "Failed to parse request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		username := requestBody.Username

		existingTrip, err := GetTripData(db, username)
		if err != nil {
			http.Error(w, "Failed to retrieve trip data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if existingTrip == nil {
			http.Error(w, "No trip data found", http.StatusNotFound)
			return
		}

		var elapsedTime int64
		if existingTrip.TripStarted && existingTrip.OriginalTripStartTime != nil {
			elapsedTime = time.Since(*existingTrip.OriginalTripStartTime).Milliseconds()
		}

		response := struct {
			TripStarted           bool      `json:"tripStarted"`
			TripStartTime         time.Time `json:"tripStartTime"`
			OriginalTripStartTime time.Time `json:"originalTripStartTime"`
			ElapsedTime           int64     `json:"elapsedTime"`
		}{
			TripStarted:           existingTrip.TripStarted,
			TripStartTime:         *existingTrip.TripStartTime,
			OriginalTripStartTime: *existingTrip.OriginalTripStartTime,
			ElapsedTime:           elapsedTime,
		}

		responseBody, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Failed to marshal response: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(responseBody)
	}
}

func GetActiveTrips(db *sql.DB) ([]models.StartEnd, error) {
	query := "SELECT username, trip_started, trip_start_time, trip_end_time FROM trip WHERE trip_started = true"
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query active trips: %w", err)
	}
	defer rows.Close()

	var trips []models.StartEnd
	for rows.Next() {
		var trip models.StartEnd
		if err := rows.Scan(&trip.Username, &trip.TripStarted, &trip.TripStartTime, &trip.TripEndTime); err != nil {
			return nil, fmt.Errorf("failed to scan trip data: %w", err)
		}
		trips = append(trips, trip)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over rows: %w", err)
	}

	return trips, nil
}
