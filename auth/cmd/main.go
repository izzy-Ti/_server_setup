package main

import (
	"log"
	"net/http"

	"github.com/izzy-Ti/_server_setup/auth/internals/db"
	"github.com/izzy-Ti/_server_setup/auth/internals/server"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	db.Connect()
	db.Migrate()

	handler := server.New()
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))

}
