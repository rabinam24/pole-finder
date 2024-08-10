package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	key   = []byte("MTK1ZWFKNZMTYMRLOS0ZMTQ2LTG1OGUTYJNLM2JHMJG4MZE1")
	store = sessions.NewCookieStore(key)

	oauth2Config = &oauth2.Config{
		ClientID:     "607168653915-f5sac4tb4mvuslkj2l0cit912nupdkr3.apps.googleusercontent.com",
		ClientSecret: "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",
		Endpoint:     google.Endpoint,
		RedirectURL:  "https://740b-45-64-160-84.ngrok-free.app/callback",
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

	fmt.Fprintln(w, "The cake is a lie!")
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
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userInfo, ok := session.Values["user_info"].(map[string]interface{})
	if !ok {
		http.Error(w, "User info not found in session", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}
