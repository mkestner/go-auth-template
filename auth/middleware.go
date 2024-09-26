package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextUserKey string

const userKey = contextUserKey("USER_KEY")

// GetUser is a helper method for retrieving user info from the context
func GetUser(ctx context.Context) *UserInfo {
	user, ok := ctx.Value(userKey).(UserInfo)
	if !ok {
		return nil
	}
	return &user
}

// Middleware is a proxying handler for ensuring authorization on protected route handlers.
func Middleware(handler http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			slog.Warn("missing or bad format of Auth header", slog.String("header", hdr))
			setErrorResponse(w, "Authorization header missing or lacks 'Bearer ' prefix", http.StatusUnauthorized)
			return
		}
		tokenString := hdr[len("Bearer "):]
		token, err := jwt.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SIGNING_KEY")), nil
		})
		if err != nil {
			slog.Warn("failed to parse token", slog.String("token", tokenString))
			msg := fmt.Sprintf("Unable to parse provided token: %s", tokenString)
			setErrorResponse(w, msg, http.StatusUnauthorized)
			return
		}
		claims, ok := token.Claims.(*customClaims)
		if !ok || !token.Valid {
			slog.Warn(
				"failed to validate token",
				slog.String("token", tokenString),
				slog.Bool("ok", ok),
				slog.Bool("valid", token.Valid),
			)
			setErrorResponse(w, "Invalid token provided", http.StatusUnauthorized)
			return
		}
		user := UserInfo{ID: claims.UserID, Email: claims.Email}
		ctx := context.WithValue(r.Context(), userKey, user)
		r = r.WithContext(ctx)
		handler(w, r)
	})
}
