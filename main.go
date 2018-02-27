package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

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

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	// TODO check state matches
	code := r.FormValue("code")

	tok, err := oauthConf.Exchange(oauth2.NoContext, code)
	client := oauthConf.Client(oauth2.NoContext, tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var userInfo gPlusResp
	err = json.Unmarshal(body, &userInfo)

	fmt.Println(string(body))

	email := userInfo.Email
	parts := strings.SplitAfter(email, "@")
	domain := parts[len(parts)-1]

	if domain != "guardian.co.uk" {
		found := email + ", " + domain

		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(found))
		fmt.Println(email, domain)
		return
	}

	// store jwt token in session

	w.Write([]byte(domain))
}

func proxyWithAuth(w http.ResponseWriter, r *http.Request) {
	g, _ := url.Parse("https://www.theguardian.com")
	proxy := httputil.NewSingleHostReverseProxy(g)
	state := "foo" // TODO randomise and confirm other side (CSRF)

	http.Redirect(w, r, oauthConf.AuthCodeURL(state), http.StatusFound)

	if isAuthed(r) {
		r.Host = r.URL.Host
		proxy.ServeHTTP(w, r)
	} else {
		auth()
	}

}

func isAuthed(r *http.Request) bool {
	// check jwt token is signed correctly with expected method
	// jwt header.payload.signature
	//
	return true
}

func auth() {
	// build a 'client' from config
	// use it to do auth flow
	// then handle token as expected...

	// note, there is a double flow: 1) get auth code 2) get token

	// redirect to google
	// then on callback validate against domain
	// store relevant info in session as jwt token with app secret

}

// func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
// 	url := googleOauthConfig.AuthCodeURL(oauthStateString)
// 	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
// }

// func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
// 	state := r.FormValue("state")
// 	if state != oauthStateString {
// 		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
// 		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
// 		return
// 	}

// 	code := r.FormValue("code")
// 	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
// 	if err != nil {
// 		fmt.Printf("Code exchange failed with '%s'\n", err)
// 		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
// 		return
// 	}

// 	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
// 	if err != nil {
// 		// handle error
// 	}
// 	defer response.Body.Close()

// 	contents, err := ioutil.ReadAll(response.Body)
// 	fmt.Fprintf(w, "Content: %s\n", contents)

// }

// cli option to filter tasks being run
// this proxy in front of kibana for security

// lambda to ingest data from sns
// lambda to write data to sns
// note, configurable per task (to include only what is needed for that env)
// we will run in a lambda but also tc scheduled task

// note this requires:

// cli flag for app to control tasks (comma-separated list?)

// some way to view kibana stats..
// okay to be ip only because no pi data!
