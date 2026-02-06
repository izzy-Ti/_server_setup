package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/gomail.v2"
)

func ParseJSON(r *http.Request, payload any) error {
	if r.Body == nil {
		return fmt.Errorf("missing req")
	}
	return json.NewDecoder(r.Body).Decode(payload)
}
func WriteJson(w http.ResponseWriter, status int, v any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}
func WriteError(w http.ResponseWriter, status int, err error) {
	WriteJson(w, status, map[string]string{"error": err.Error()})
}
func IsProd() bool {
	return os.Getenv("APP_ENV") == "production"
}
func SendWelcomeEmail(to, name, token string) error {
	verificationUrl := fmt.Sprintf("https://fmbls.vercel.app/verifyemail")

	m := gomail.NewMessage()

	m.SetHeader("From", os.Getenv("EMAIL"))
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Welcome! Please verify your email")
	m.SetBody("text/html", fmt.Sprintf(`
        <p>Hi %s,</p>
        <p>Welcome! Please verify your email by clicking the link below:</p>
        <a href="%s">Verify Email</a>
        <p>If this wasn’t you, please ignore this email.</p>
    `, name, verificationUrl))

	d := gomail.NewDialer("smtp.gmail.com", 465, os.Getenv("EMAIL"), os.Getenv("PASSWORD"))
	return d.DialAndSend(m)
}
func UserId(tokenStr string) (string, error) {
	secret := os.Getenv("JWT_KEY")
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return "", errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}
	userID, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("sub not found")
	}

	return userID, nil
}
