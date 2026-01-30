package server

import (
	"net/http"

	"github.com/gorilla/mux"
)

func New() http.Handler {
	r := mux.NewRouter()
	//api := r.PathPrefix("/api/v1").Subrouter()
	r.HandleFunc("/api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	return r
}
