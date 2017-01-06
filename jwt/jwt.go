// Copyright 2017 Nick Vellios. All rights reserved.
// Use of this source code is governed by the Unlicense license.
// For more information, please refer to http://unlicense.org/

// Package jwt is a barebones JSON Web Token implementation in Go
//
// JWTs are generated from a map of string keys and values, and an
// expiration time in seconds.  The JWT is signed with HMAC SHA.

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/nickvellios/golang-web-app/ncrypt"
)

// salt is a randomly generated string used when signing a JWT
var salt string

// init creates the random salt.
func init() {
	rand.Seed(time.Now().UnixNano())
	// Create a random string of random length for our salt
	randombytes := ncrypt.RandomBytes(rand.Intn(64))
	if randombytes == nil {
		panic(errors.New("Error creating random salt"))
	}
	salt = string(randombytes)
}

// Generate compiles and signs a JWT from a claim and an expiration time in seconds from current time.
func Generate(claim map[string]string, exp int) string {
	ex := time.Now().Add(time.Second * time.Duration(exp))
	expiration := ex.Format("2006-01-02 15:04:05")
	// Build the jwt header by hand since alg and typ aren't going to change (for now)
	header := base64.StdEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","exp":"` + expiration + `"}`))
	// Build json payload and base64 encode it
	pl2, err := json.Marshal(claim)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}
	payload := base64.StdEncoding.EncodeToString([]byte(pl2))
	// Create a new secret from our salt and the paylod json string.
	secret := ncrypt.SHA2(salt + string(pl2))
	// Build signature with the new secret and base64 encode it.
	hash := ncrypt.Hmac256(header+"."+payload, secret)
	signature := base64.StdEncoding.EncodeToString([]byte(hash))
	jwt := header + "." + payload + "." + signature
	return jwt
}

// Decode decodes a JWT and returns the payload as a map[string]string.
func Decode(jwt string) (map[string]string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, errors.New("Invalid JWT Structure")
	}
	header, _ := base64.StdEncoding.DecodeString(parts[0])
	payload, _ := base64.StdEncoding.DecodeString(parts[1])
	signature, _ := base64.StdEncoding.DecodeString(parts[2])
	// JSON decode payload
	var pldat map[string]string
	if err := json.Unmarshal(payload, &pldat); err != nil {
		fmt.Println(err.Error())
	}
	// JSON decode header
	var headdat map[string]interface{}
	if err := json.Unmarshal(header, &headdat); err != nil {
		fmt.Println(err.Error())
	}
	// Extract and parse expiration date from header
	layout := "2006-01-02 15:04:05"
	exp := headdat["exp"].(string)
	expParsed, err := time.ParseInLocation(layout, exp, time.Now().Location())
	if err != nil {
		fmt.Println(err)
	}
	// Check how old the JWT is.  Return an error if it is expired
	now := time.Now()
	if now.After(expParsed) {
		return nil, errors.New("Expired JWT")
	}
	// This probably should be one of the first checks, preceeding the date check.  If the signature of the JWT doesn't match there is likely fuckery afoot
	ha := ncrypt.Hmac256(string(parts[0])+"."+string(parts[1]), ncrypt.SHA2(salt+string(payload)))
	if ha != string(signature) {
		return nil, errors.New("Invalid JWT signature")
	}

	return pldat, nil
}

// DecodeFromCookie extracts and decodes the JWT payload from a given http.Request and cookie name
func DecodeFromCookie(r *http.Request, cookieName string) (map[string]string, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || len(cookie.Value) < 1 {
		return nil, errors.New("No cookie set")
	}

	theJWT, err := Decode(cookie.Value)
	if err != nil {
		return nil, err
	}

	return theJWT, nil
}
