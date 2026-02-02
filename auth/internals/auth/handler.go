package auth

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/izzy-Ti/_server_setup/auth/internals/db"
	"github.com/izzy-Ti/_server_setup/auth/internals/models"
	"github.com/izzy-Ti/_server_setup/auth/internals/utils"
	"golang.org/x/crypto/bcrypt"
)

type RegisterRequest struct {
	Name     string `json: "Name"`
	Email    string `json: "Email"`
	Password string `json: "Password"`
}
type LoginRequest struct {
	Email    string `json: "Email"`
	Password string `json: "Password"`
}
type Response struct {
	Message string `json:"Token"`
}

var jwtSecret = []byte(os.Getenv("JWT_KEY"))

func Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	err := utils.ParseJSON(r, &req)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}
	var userModel models.User
	UserEmail := db.DB.Where("email = ?", req.Email).First(&userModel).Error
	if UserEmail == nil {
		utils.WriteJson(w, http.StatusUnauthorized, "Email already exists")
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	user := models.User{
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hashedPassword),
	}
	if err := db.DB.Create(&user).Error; err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		HttpOnly: utils.IsProd(),
		SameSite: func() http.SameSite {
			if utils.IsProd() {
				return http.SameSiteStrictMode
			}
			return http.SameSiteLaxMode
		}(),
		Path:    "/",
		Expires: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	if err := utils.SendWelcomeEmail(req.Email, req.Name, tokenString); err != nil {
		log.Println("Email send failed:", err)
		return
	}

	resp := Response{Message: "Registration successful"}
	utils.WriteJson(w, http.StatusOK, resp)

}
func Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	err := utils.ParseJSON(r, &req)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}
	var user models.User
	if err := db.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		utils.WriteError(w, http.StatusUnauthorized, err)
		return
	}
	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(req.Password),
	); err != nil {
		utils.WriteError(w, http.StatusUnauthorized, err)
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		HttpOnly: utils.IsProd(),
		SameSite: func() http.SameSite {
			if utils.IsProd() {
				return http.SameSiteStrictMode
			}
			return http.SameSiteLaxMode
		}(),
		Path:    "/",
		Expires: time.Now().Add(24 * time.Hour),
	})
	res := "login Successfully"
	resp := Response{
		Message: res,
	}
	utils.WriteJson(w, http.StatusOK, resp)
}
