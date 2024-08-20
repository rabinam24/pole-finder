package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	key   = []byte("MTK1ZWFKNZMTYMRLOS0ZMTQ2LTG1OGUTYJNLM2JHMJG4MZE1")
	store = sessions.NewCookieStore(key)

	oauth2Config = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Endpoint:     google.Endpoint,
		RedirectURL:  "https://5e28-202-79-62-4.ngrok-free.app",
		Scopes:       []string{"openid", "profile", "email"},
	}
)

func HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code is missing", http.StatusBadRequest)
		log.Printf("Authorizaiton code is missing")
		return
	}

	ctx := context.Background()
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusBadRequest)
		return
	}

	client := oauth2Config.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to decode user info: "+err.Error(), http.StatusBadRequest)
		return
	}

	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["authenticated"] = true
	session.Values["user_info"] = userInfo
	session.Save(r, w)
	log.Printf("Session after saving: %+v", session.Values)
	log.Printf("Session ID: %s", session.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func Login(w http.ResponseWriter, r *http.Request) {
	url := oauth2Config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["authenticated"] = false
	session.Save(r, w)

	logoutURL := fmt.Sprintf("https://oauth2.googleapis.com/revoke?token=%s",
		session.Values["oauth_token"])
	http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
}

func Secret(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	fmt.Fprintln(w, "The liverpool is a GOAT!")
}

func ProxyOAuthToken(w http.ResponseWriter, r *http.Request) {
	target, _ := url.Parse("https://www.googleapis.com")
	proxy := httputil.NewSingleHostReverseProxy(target)

	r.URL.Path = "/oauth2/v4/token"
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Set("Access-Control-Allow-Origin", "*")
		return nil
	}

	proxy.ServeHTTP(w, r)
}

func GetUserInfo(w http.ResponseWriter, r *http.Request) {
	// Get the session from the request
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve user info from the session
	userInfo, ok := session.Values["user_info"].(map[string]interface{})
	if !ok {
		http.Error(w, "User info not found in session", http.StatusNotFound)
		return
	}

	// Respond with user info in JSON format
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		http.Error(w, "Failed to encode user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

var db *sql.DB

func saveUser(db *sql.DB, auth0UserID, email, name string) error {
	var id int
	err := db.QueryRow("SELECT id FROM user_info WHERE auth0_user_id = $1", auth0UserID).Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			// User does not exist, insert a new record
			_, err = db.Exec(
				`INSERT INTO user_info (auth0_user_id, email, name) VALUES ($1, $2, $3)`,
				auth0UserID, email, name,
			)
			if err != nil {
				return fmt.Errorf("failed to insert user: %v", err)
			}
		} else {
			return fmt.Errorf("failed to check if user exists: %v", err)
		}
	} else {
		// User exists, you can update their information if needed
		_, err = db.Exec(
			`UPDATE user_info SET email = $1, name = $2 WHERE auth0_user_id = $3`,
			email, name, auth0UserID,
		)
		if err != nil {
			return fmt.Errorf("failed to update user: %v", err)
		}
	}

	return nil
}

func SaveUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "cookie-name")
		if err != nil {
			http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
			log.Printf("Failed to get session in SaveUser: %v", err)
			return
		}

		// Debugging: Print session values
		log.Printf("Session values: %+v", session.Values)

		userInfo, ok := session.Values["user_info"].(map[string]interface{})
		if !ok {
			http.Error(w, "User info not found in session", http.StatusInternalServerError)
			log.Println("User info not found in session during SaveUser")
			return
		}

		auth0UserID, ok := userInfo["sub"].(string)
		if !ok {
			http.Error(w, "Invalid Auth0 user ID", http.StatusInternalServerError)
			log.Println("Invalid Auth0 user ID")
			return
		}

		email, ok := userInfo["email"].(string)
		if !ok {
			http.Error(w, "Invalid email", http.StatusInternalServerError)
			log.Println("Invalid email")
			return
		}

		name, ok := userInfo["name"].(string)
		if !ok {
			http.Error(w, "Invalid name", http.StatusInternalServerError)
			log.Println("Invalid name")
			return
		}

		// Save user to the database
		if err := saveUser(db, auth0UserID, email, name); err != nil {
			http.Error(w, "Failed to save user: "+err.Error(), http.StatusInternalServerError)
			log.Printf("Failed to save user: %v", err)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "User saved successfully")
	}
}
