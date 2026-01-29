package api

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type ApiServer struct {
	addr string
	db   *sql.DB
}

func NewApiServer(addr string, db *sql.DB) *ApiServer {
	return &ApiServer{
		addr: addr,
		db:   db,
	}
}
func (s *ApiServer) Run() error {
	router := mux.NewRouter()
	subrouter := router.PathPrefix("api/v1").subrouter()
	subrouter.Handle
	log.Println("listening on", s.addr)
	return http.ListenAndServe(s.addr, router)
}
