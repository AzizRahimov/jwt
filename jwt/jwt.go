package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

func main() {
	payload := struct {
		Id  int   `json:"id"`
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}{
		Id:  1,
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(time.Hour * 10).Unix(),
	}

	secret := []byte("very-secret-token")

	token, err := Encode(payload, secret)
	if err != nil {
		panic(err)
	}
	log.Print(token)
}

func Encode(payload interface{}, secret []byte) (token string, err error) {
	header := struct {
		Alg string `json:"alg"` // tag .Tag, Lookup("json")
		Typ string `json:"typ"` // tag .Tag, Lookup("json")
	}{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(fmt.Sprintf("%s.%s", headerEncoded, payloadEncoded)))
	signature := h.Sum(nil)

	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signatureEncoded), nil
}
