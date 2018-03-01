package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

type gPlusResp struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

var (
	oauthConf = &oauth2.Config{
		RedirectURL:  "",
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
	var port = flag.Int("port", 80, "port to listen on")
	var target = flag.String("target", "", "target host and port, e.g. 'http://localhost:3000'")
	var host = flag.String("host", "http://localhost", "hostname, used for oauth callback")
	var help = flag.Bool("help", false, "Get program help")

	flag.Parse()

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *target == "" {
		log.Println("Must provide target argument")
		flag.PrintDefaults()
		log.Fatal()
	}

	if oauthConf.ClientID == "" || oauthConf.ClientSecret == "" {
		log.Fatal("Must provide google client ID and client secret as env vars (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET")
	}

	addr := fmt.Sprintf(":%d", *port)

	targetUrl, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("Invalid target host (%s)", *target)
	}

	hostUrl, err := url.Parse(*host)
	if err != nil {
		log.Fatalf("Invalid host (%s)", *host)
	}

	if *port == 80 {
		oauthConf.RedirectURL = fmt.Sprintf("%s/oauth2callback", hostUrl.String())
	} else {
		oauthConf.RedirectURL = fmt.Sprintf("%s:%d/oauth2callback", hostUrl.String(), *port)
	}

	http.HandleFunc("/", proxyWithAuth(targetUrl))
	http.HandleFunc("/oauth2callback", handleGoogleLogin)
	fmt.Println(http.ListenAndServe(addr, nil))
}

func proxyWithAuth(target *url.URL) func(w http.ResponseWriter, r *http.Request) {
	proxy := httputil.NewSingleHostReverseProxy(target)

	return func(w http.ResponseWriter, r *http.Request) {
		cookies := r.Cookies()
		var token string
		for _, c := range cookies {
			if c.Name == "session" {
				token = c.Value
			}
		}

		_, err := verifyToken(token, []byte("foo"), "guardian.co.uk")
		if err != nil {
			state := "foo" // TODO randomise and confirm other side (CSRF)
			http.Redirect(w, r, oauthConf.AuthCodeURL(state), http.StatusFound)
			return
		}

		r.Host = r.URL.Host // TODO remind myself why this works
		proxy.ServeHTTP(w, r)
	}
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
	domain := domainFromEmail(email)

	if domain != "guardian.co.uk" || !userInfo.EmailVerified {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorised (unsupported email domain, or email not verified)"))
		return
	}

	hmacSecret := []byte("foo")
	sessionToken, err := newSessionToken(email, jwt.SigningMethodHS256, hmacSecret)

	session := http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Domain:   strings.Split(r.Host, ":")[0], // drop port if present
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // TODO make secure when on https
	}

	w.Header().Add("Set-Cookie", session.String())
	http.Redirect(w, r, "/", http.StatusFound)
}

func newSessionToken(email string, signingMethod jwt.SigningMethod, secret []byte) (string, error) {
	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().AddDate(0, 0, 30).Unix(),
	})

	return token.SignedString(secret)
}

func verifyToken(token string, hmacSecret []byte, expectedDomain string) (string, error) {
	userToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		method, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok || method.Alg() != "HS256" {
			return nil, fmt.Errorf("unexpected signing method")
		}

		return hmacSecret, nil
	})
	if err != nil {
		return "", fmt.Errorf("Token invalid (%s)", err.Error())
	}

	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("Token invalid (unable to parse jwt claims)")
	}

	email := claims["email"].(string)

	if domain := domainFromEmail(email); domain != expectedDomain {
		return "", errors.New("Token invalid (domain did not match)")
	}

	return email, nil
}

func domainFromEmail(email string) string {
	parts := strings.SplitAfter(email, "@")
	return parts[len(parts)-1]
}
