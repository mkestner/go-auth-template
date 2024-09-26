package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestMiddlewareInvalidAuthHeader(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be invoked")
	}

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"dont":"care"}`)
	req, _ := http.NewRequest("POST", "/protected", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "foo")

	middleware := Middleware(handler)
	middleware.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	jsonerr := &ErrorResponse{}
	if err := json.Unmarshal(body, jsonerr); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if !strings.Contains(jsonerr.Error, "Authorization header missing or lacks 'Bearer ' prefix") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestMiddlewareMissingAuthHeader(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be invoked")
	}

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"dont":"care"}`)
	req, _ := http.NewRequest("POST", "/protected", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	middleware := Middleware(handler)
	middleware.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	jsonerr := &ErrorResponse{}
	if err := json.Unmarshal(body, jsonerr); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if !strings.Contains(jsonerr.Error, "Authorization header missing or lacks 'Bearer ' prefix") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestMiddlewareGarbageToken(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be invoked")
	}

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"dont":"care"}`)
	req, _ := http.NewRequest("POST", "/protected", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token")

	middleware := Middleware(handler)
	middleware.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	jsonerr := &ErrorResponse{}
	if err := json.Unmarshal(body, jsonerr); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if !strings.Contains(jsonerr.Error, "Unable to parse provided token") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func createTestJWT(key string) (string, error) {
	claims := customClaims{}
	claims.UserID = "123"
	claims.Email = "TestUser@example.com"
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	claims.RegisteredClaims.Issuer = os.Getenv("JWT_AUTHORITY")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func TestAuthzMiddlewareInvalidTokenSignature(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be invoked")
	}

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"dont":"care"}`)
	req, _ := http.NewRequest("POST", "/protected", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	token, err := createTestJWT("garbage_key")
	if err != nil {
		t.Error("Failed to create test token")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	middleware := Middleware(handler)
	middleware.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	jsonerr := &ErrorResponse{}
	if err := json.Unmarshal(body, jsonerr); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if !strings.Contains(jsonerr.Error, "Unable to parse provided token") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestAuthzMiddlewareSuccess(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		user := GetUser(r.Context())
		if user == nil {
			t.Fatal("unable to retrieve user value from context")
		}
		if user.ID != "123" || user.Email != "TestUser@example.com" {
			t.Error("context user value is invalid")
		}
	}

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"dont":"care"}`)
	req, _ := http.NewRequest("POST", "/protected", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	token, err := createTestJWT(os.Getenv("JWT_SIGNING_KEY"))
	if err != nil {
		t.Error("Failed to create test token")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	middleware := Middleware(handler)
	middleware.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}
}
