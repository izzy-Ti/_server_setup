package user

import (
	"net/http"

	"github.com/gorilla/mux"
)

type Handler struct {
}

func NewHandler() *Handler {
	return &Handler{}
}
func (h *Handler) RegisterRoute(router *mux.Router) {
	router.HandleFunc("/login", h.handLogin).Methods("POST")
	router.HandleFunc("/register", h.handRegister).Methods("POST")
}
func (h *Handler) handLogin(w http.ResponseWriter, r *http.Request) {

}
func (h *Handler) handRegister(w http.ResponseWriter, r *http.Request) {

}
