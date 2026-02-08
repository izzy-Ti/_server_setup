package middleware

import (
	"context"
	"net/http"
	"os"

	"github.com/izzy-Ti/_server_setup/auth/internals/utils"
)

var jwtSecret = []byte(os.Getenv("JWT_KEY"))

func IsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("token")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		userID, err := utils.UserId(token.Value, []byte(jwtSecret))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		user, err := utils.GetUserByID(userID)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
