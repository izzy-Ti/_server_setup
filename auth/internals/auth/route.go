package auth

import "github.com/gorilla/mux"

func AuthRoutes(r *mux.Router) {
	userRouter := r.PathPrefix("/user").Subrouter()
	userRouter.HandleFunc("/register", Register).Methods("POST")
	userRouter.HandleFunc("/login", Login).Methods("POST")
}
