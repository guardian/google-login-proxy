package main

import (
	"github.com/dgrijalva/jwt-go"
	"testing"
	"time"
)

func TestJwtAcceptsValid(t *testing.T) {
	secret := []byte("hmac-secret")
	token, _ := newSessionToken("foo@example.com", jwt.SigningMethodHS256, secret)
	email, err := verifyToken(token, secret, "example.com")

	if err != nil || email != "foo@example.com" {
		t.Fail()
	}
}

func TestJwtRejectsDiffAlgorithm(t *testing.T) {
	secret := []byte("hmac-secret")
	token, _ := newSessionToken("foo@example.com", jwt.SigningMethodHS384, secret)
	_, err := verifyToken(token, secret, "example.com")

	checkErr(t, err, "Token invalid (unexpected signing method)")
}

func TestJwtRejectsExpired(t *testing.T) {
	secret := []byte("hmac-secret")
	unsigned := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": "foo@example.com",
		"exp":   time.Now().AddDate(0, 0, -30).Unix(),
	})
	token, _ := unsigned.SignedString(secret)

	_, err := verifyToken(token, secret, "example.com")

	checkErr(t, err, "Token invalid (Token is expired)")
}

func TestJwtRejectsRejectsBadDomain(t *testing.T) {
	secret := []byte("hmac-secret")
	token, _ := newSessionToken("foo@bad-domain.com", jwt.SigningMethodHS256, secret)
	_, err := verifyToken(token, secret, "example.com")

	checkErr(t, err, "Token invalid (domain did not match)")
}

func checkErr(t *testing.T, err error, want string) {
	if err == nil || err.Error() != want {
		t.Errorf("Failed with: %v", err)
	}
}
