package config

import (
	"fmt"
	"os"
)

type config struct {
	PublicHost string
	Port       string
	DBuser     string
	DBPassword string
	DBAddress  string
	DBName     string
}

var ENV = initConfig()

func initConfig() config {
	return config{
		PublicHost: getEnv("PUBLIC_HOST", "http://localhost:3306/"),
		Port:       getEnv("PORT", "3306"),
		DBuser:     getEnv("DB_USER", "Golang"),
		DBPassword: getEnv("DB_PASSWORD", "0911700417"),
		DBAddress:  fmt.Sprintf("%s:%s", getEnv("DB_HOST", "127.0.0.1"), getEnv("DB_PORT", "3306")),
		DBName:     getEnv("DB_NAME", "Golang"),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}