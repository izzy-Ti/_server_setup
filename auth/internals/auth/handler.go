package auth

import (
	"net/http"

	"gorm.io/gorm"
)

type Handler struct{
	db *gorm.DB
}

func Register(w http.ResponseWriter, r *http.Request) {

}