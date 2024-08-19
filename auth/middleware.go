package auth

import (
	"context"
	"net/http"
	"strings"

	api "github.com/daripadabengong/api-utils"
)

type contextKey string

const UserDetailsKey contextKey = "userDetails"

func JWTMiddleware(client *AuthClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				api.JSONError(w, "Authorization header missing", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				api.JSONError(w, "Invalid Authorization header format", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				api.JSONError(w, "Authorization header format must be Bearer {token}", http.StatusUnauthorized)
				return
			}

			user, err := client.ParseToken(tokenString)
			if err != nil {
				api.JSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ctx := context.WithValue(r.Context(), UserDetailsKey, user)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

func GetUserDetails(ctx context.Context) (*User, bool) {
	userDetails, ok := ctx.Value(UserDetailsKey).(*User)
	return userDetails, ok
}
