package models

import "time"

type FormData struct {
	ID                 int       `json:"id"`
	Location           string    `json:"location"`
	Latitude           float64   `json:"latitude"`
	Longitude          float64   `json:"longitude"`
	SelectPole         string    `json:"selectpole"`
	SelectPoleStatus   string    `json:"selectpolestatus"`
	SelectPoleLocation string    `json:"selectpolelocation"`
	Description        string    `json:"description"`
	PoleImage          string    `json:"poleimage_url"`
	AvailableISP       string    `json:"availableisp"`
	SelectISP          string    `json:"selectisp"`
	MultipleImages     []string  `json:"multipleimages_urls"`
	CreatedAt          time.Time `json:"created_at"`
}

type GPSData struct {
	ID        int       `json:"id"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	Date      time.Time `json:"date"`
}
