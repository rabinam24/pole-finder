package models

import "time"

type StartEnd struct {
	Username              string     `json:"username"`
	TripStarted           bool       `json:"tripStarted"`
	TripStartTime         *time.Time `json:"tripStartTime"`
	TripEndTime           *time.Time `json:"tripEndTime"`
	OriginalTripStartTime *time.Time `json:"originalTripStartTime"`
}
