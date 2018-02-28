package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// For info on JWT see: https://tools.ietf.org/html/rfc7519
// For info on oauth see: ..

type gPlusResp struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

var (
	oauthConf = &oauth2.Config{
		RedirectURL:  "http://localhost:3000/oauth2callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes: []string{"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint: google.Endpoint,
	}
	// Some random string, random for each request
	oauthStateString = "random"
)

func main() {
	http.HandleFunc("/", proxyWithAuth)
	http.HandleFunc("/oauth2callback", handleGoogleLogin)
	fmt.Println(http.ListenAndServe(":3000", nil))
}

func proxyWithAuth(w http.ResponseWriter, r *http.Request) {
	g, _ := url.Parse("https://www.theguardian.com")
	proxy := httputil.NewSingleHostReverseProxy(g)

	cookies := r.Cookies()
	var session string
	for _, c := range cookies {
		if c.Name == "session" {
			session = c.Value
		}
	}

	_, err := getEmailFromToken(session, []byte("foo"))
	if err != nil {
		state := "foo" // TODO randomise and confirm other side (CSRF)
		http.Redirect(w, r, oauthConf.AuthCodeURL(state), http.StatusFound)
		return
	}

	r.Host = r.URL.Host // TODO remind myself why this works
	proxy.ServeHTTP(w, r)
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	// TODO check state matches
	code := r.FormValue("code")

	tok, err := oauthConf.Exchange(oauth2.NoContext, code)
	client := oauthConf.Client(oauth2.NoContext, tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Unauthorised (%s)", err.Error())))
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var userInfo gPlusResp
	err = json.Unmarshal(body, &userInfo)

	email := userInfo.Email
	parts := strings.SplitAfter(email, "@")
	domain := parts[len(parts)-1]

	if domain != "guardian.co.uk" || !userInfo.EmailVerified {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorised (unsupported email domain, or email not verified)"))
		return
	}

	hmacSecret := []byte("foo")
	sessionToken, err := newSessionToken(email, hmacSecret)

	session := http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Domain:   "localhost",
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // TODO make secure when on https
	}

	w.Header().Add("Set-Cookie", session.String())
	http.Redirect(w, r, "/", http.StatusFound)
}

func newSessionToken(email string, hmacSecret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().AddDate(0, 0, 30).Unix(),
	})

	return token.SignedString(hmacSecret)
}

func getEmailFromToken(token string, hmacSecret []byte) (string, error) {
	userToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return hmacSecret, nil
	})
	if err != nil {
		return "", fmt.Errorf("Unable to parse token: %s", err.Error())
	}

	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("Unable to parse jwt claims")
	}

	if !userToken.Valid {
		return "", errors.New("Token is not valid (perhaps it has expired?)")
	}

	return claims["email"].(string), nil
}
