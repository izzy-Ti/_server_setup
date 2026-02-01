package models

type userRole string

const (
	ADMIN userRole = "ADMIN"
	USER  userRole = "USER"
)

type User struct {
	ID               uint     `gorm:"primaryKey"`
	Name             string   `gorm:"not null"`
	Email            string   `gorm:"uinqueIndex;not null"`
	Password         string   `gorm:"not null"`
	verifyOTP        string   `gorm:"default:''"`
	OTPExpireAt      int      `gorm:"default:0"`
	IsAccVerified    bool     `gorm:"default:false"`
	ResetOTP         string   `gorm:"default:''"`
	ResetOTPExpireAt int      `gorm:"default:0"`
	avater           string   `gorem:"default:''"`
	role             userRole `gorem:"default: 'USER'"`
}
