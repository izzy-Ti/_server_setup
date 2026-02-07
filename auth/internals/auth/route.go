package auth

import "github.com/gorilla/mux"

func AuthRoutes(r *mux.Router) {
	userRouter := r.PathPrefix("/user").Subrouter()
	userRouter.HandleFunc("/register", Register).Methods("POST")
	userRouter.HandleFunc("/login", Login).Methods("POST")
	userRouter.HandleFunc("/logout", Logout).Methods("POST")
	userRouter.HandleFunc("/sendotp", SendVerifyOTP).Methods("POST")
	userRouter.HandleFunc("/verifyotp", VerifyOTP).Methods("POST")
}
