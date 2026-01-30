package db

import (
	"log"

	"github.com/izzy-Ti/_server_setup/auth/internals/auth"
	"gorm.io/gorm"
)

func Migrate(DB *gorm.DB) {
	err := DB.AutoMigrate(&auth.User{})
	if err != nil {
		log.Fatal("Migration failed:", err)
	}
	log.Println("Database migrated")
}
