package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// LoginUser is a route handler for the login capability. It expects a json body of type Credentials
// and returns a TokenResponse on success or an ErrorResponse on failure.
func LoginUser(provider Provider) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input Credentials
		err := decodeJSONBody(w, r, &input)
		if err != nil {
			var mr *malformedRequest
			if errors.As(err, &mr) {
				setErrorResponse(w, mr.msg, mr.status)
			} else {
				slog.Error("error decoding json body", slog.String("error", err.Error()))
				setErrorResponse(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		user, err := provider.GetUser(input.Email)
		if err != nil {
			slog.Warn("error looking up user", slog.String("email", input.Email), slog.String("error", err.Error()))
			setErrorResponse(w, "unknown email: must be a registered user", http.StatusBadRequest)
			return
		}

		err = bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(input.Password))
		if err != nil {
			slog.Warn(
				"password comparison to hashed password failed",
				slog.String("email", input.Email),
				slog.String("error", err.Error()),
			)
			setErrorResponse(w, "incorrect password: does not match the registered password for user", http.StatusBadRequest)
			return
		}

		token, err := createAccessToken(*user)
		if err != nil {
			slog.Error(
				"failed to create token",
				slog.String("email", input.Email),
				slog.String("error", err.Error()),
			)
			setErrorResponse(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		refresh, err := createRefreshToken(provider, user.ID)
		if err != nil {
			slog.Error(
				"failed to create refresh token",
				slog.String("email", input.Email),
				slog.String("error", err.Error()),
			)
			setErrorResponse(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		tr := TokenResponse{UserID: string(user.ID), AccessToken: string(token), RefreshToken: string(refresh)}
		json.NewEncoder(w).Encode(tr)
	})
}

// RefreshUser is a route handler for the token refresh capability. It expects a json body of type RefreshRequest
// and returns a TokenResponse on success or an ErrorResponse on failure.
func RefreshUser(provider Provider) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input RefreshRequest
		err := decodeJSONBody(w, r, &input)
		if err != nil {
			var mr *malformedRequest
			if errors.As(err, &mr) {
				setErrorResponse(w, mr.msg, mr.status)
			} else {
				slog.Error("error decoding json body", slog.String("error", err.Error()))
				setErrorResponse(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		refresh, userID, err := invokeRefreshToken(provider, input.RefreshToken)
		if err != nil {
			var invalid invalidTokenError
			var invoked invokedTokenError
			if errors.As(err, &invalid) || errors.As(err, &invoked) {
				setErrorResponse(w, err.Error(), http.StatusBadRequest)
			} else {
				setErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		user, err := provider.GetUserByID(userID)
		if err != nil {
			slog.Error(
				"failed to fetch user info",
				slog.String("user_id", string(userID)),
				slog.String("error", err.Error()),
			)
			setErrorResponse(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		access, err := createAccessToken(*user)
		if err != nil {
			slog.Error(
				"failed to create token",
				slog.String("email", user.Email),
				slog.String("error", err.Error()),
			)
			setErrorResponse(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		response := TokenResponse{UserID: string(userID), AccessToken: string(access), RefreshToken: string(refresh)}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})
}

// RegisterUser is a route handler for the user registration capability. It expects a json body of type Credentials
// and returns Credentials on success or an ErrorResponse on failure.
func RegisterUser(provider Provider) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input Credentials
		err := decodeJSONBody(w, r, &input)
		if err != nil {
			var mr *malformedRequest
			if errors.As(err, &mr) {
				setErrorResponse(w, mr.msg, mr.status)
			} else {
				slog.Error("error decoding json body", slog.String("error", err.Error()))
				setErrorResponse(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		_, err = mail.ParseAddress(input.Email)
		if err != nil {
			slog.Warn(
				"failed to validate email",
				slog.String("email", input.Email),
				slog.String("error", err.Error()),
			)
			setErrorResponse(w, fmt.Sprintf("invalid email (%s): must be a valid email address", input.Email), http.StatusBadRequest)
			return
		}

		if err := validatePassword(input.Password); err != nil {
			var cause string
			var invPw InvalidPasswordError
			if errors.As(err, &invPw) {
				cause = invPw.cause
			}
			slog.Warn(
				"failed to validate password format",
				slog.String("email", input.Email),
				slog.String("cause", cause),
				slog.String("error", err.Error()),
			)
			setErrorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		err = provider.InsertUser(input.Email, input.Password)
		if err != nil {
			slog.Error(
				"failed to insert user",
				slog.String("email", input.Email),
				slog.String("error", err.Error()),
			)
			setErrorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		input.Password = "********"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(input)
	})
}

// InvalidPasswordError is returned when a password doesn't meet requirements
type InvalidPasswordError struct {
	cause string
}

func (f InvalidPasswordError) Error() string {
	return "invalid password: must be 8 or more characters and contain an upper and lower case character and a numeric char"
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return InvalidPasswordError{"short"}
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	for _, r := range password {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
		if unicode.IsDigit(r) {
			hasDigit = true
		}
	}

	if !hasDigit || !hasLower || !hasUpper {
		var cause string
		if !hasDigit {
			cause += "MissingDigit"
		}
		if !hasLower {
			cause += "MissingLower"
		}
		if !hasUpper {
			cause += "MissingUpper"
		}
		return InvalidPasswordError{cause}
	}

	return nil
}
