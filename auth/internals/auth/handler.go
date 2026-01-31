package auth

import (
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
type RegisterResponse struct {
	Token string `json:"Token"`
}

var jwtSecret = []byte(os.Getenv("JWT_KEY"))

func Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	err := utils.ParseJSON(r, &req)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
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
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	resp := RegisterResponse{Token: tokenString}
	utils.WriteJson(w, http.StatusOK, resp)

}
func Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	err := utils.ParseJSON(r, &req)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err)
		return
	}

}
