package ncrypt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

func Hmac256(message, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func SHA2(text string) string {
	hasher := sha256.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func HashPass(pass []byte) ([]byte, error) {
	pass, err := bcrypt.GenerateFromPassword(pass, 10)
	if err != nil {
		return nil, err
	}

	return pass, nil
}

func CheckPassHash(hash, pass []byte) error {
	return bcrypt.CompareHashAndPassword(hash, pass)
}

func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil
	}
	return b
}
