package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func TestValidatePassword(t *testing.T) {
	var tests = []struct {
		name        string
		input       string
		expectError bool
	}{
		{"fail too short", "1234567", true},
		{"fail no digit", "aBcdefgh", true},
		{"fail no lower", "ABCDEFGH123", true},
		{"fail no upper", "abcdefgh123", true},
		{"pass", "aB1cD2eF3gH4", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePassword(test.input)
			hasError := err != nil
			if hasError != test.expectError {
				expectation := "unexpected"
				if test.expectError {
					expectation = "expected"
				}
				t.Errorf("error %s for input %s", expectation, test.input)
			}
		})
	}
}

func TestLoginUserSuccess(t *testing.T) {
	email := "abcDEF123@example.com"
	password := "abcDEF123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	mock := mockProvider{
		MockGetUser: func(in_email string) (*UserInfo, error) {
			if in_email != email {
				t.Fatalf("unexpected email received by GetUser method: %s", in_email)
			}
			return &UserInfo{Email: email, HashedPassword: hashedPassword, ID: "1"}, nil
		},
		MockInsertRefreshToken: func(userID UserID) (TokenID, error) {
			if userID != "1" {
				t.Error("unexpected userid in CreateRefreshToken")
			}
			return "123", nil
		},
	}
	handler := LoginUser(mock)
	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"abcDEF123@example.com", "password": "abcDEF123"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	tokenResponse := &TokenResponse{}
	if err := json.Unmarshal(body, tokenResponse); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if tokenResponse.UserID != "1" {
		t.Errorf("unexpected user id in response: %s", string(body))
	}

	token, err := jwt.Parse(tokenResponse.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SIGNING_KEY")), nil
	})
	if err != nil {
		t.Fatalf("unable to parse token: %v", err)
	}
	if !token.Valid {
		t.Errorf("token failed validation")
	}
}

func TestLoginUserBadJson(t *testing.T) {
	mock := &mockProvider{MockGetUser: func(string) (*UserInfo, error) {
		t.Fatal("unexpected invocation of GetUser method")
		return nil, nil
	}}
	handler := LoginUser(mock)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"bad":"json"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
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

	if !strings.Contains(jsonerr.Error, "Request body contains unknown field") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestLoginUserUnknownEmail(t *testing.T) {
	mock := &mockProvider{MockGetUser: func(email string) (*UserInfo, error) {
		return nil, fmt.Errorf("unknown email provided: %s", email)
	}}
	handler := LoginUser(mock)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"short", "password": "abdDEF123"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
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

	if !strings.Contains(jsonerr.Error, "unknown email: must be a registered user") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestLoginUserInvalidPassword(t *testing.T) {
	mock := mockProvider{MockGetUser: func(string) (*UserInfo, error) {
		return &UserInfo{Email: "abdDEF123@example.com", HashedPassword: []byte("garbage"), ID: "1"}, nil
	}}
	handler := LoginUser(mock)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"abcDEF123@example.com", "password": "abdDEF123"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
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

	if !strings.Contains(jsonerr.Error, "incorrect password") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRefreshUserSuccess(t *testing.T) {
	mock := &mockProvider{
		MockT: t,
		MockGetUserByID: func(userID UserID) (*UserInfo, error) {
			if userID != "1" {
				t.Error("unexpected userID in GetUserByID")
			}
			return &UserInfo{ID: userID, Email: "user@example.com"}, nil
		},
		MockGetRefreshToken: func(tokenID TokenID) (*RefreshTokenInfo, error) {
			if tokenID != "123" {
				t.Error("unexpected tokenID in GetRefreshToken")
			}
			return &RefreshTokenInfo{ID: TokenID("123"), UserID: UserID("1"), Invoked: false}, nil
		},
		MockInsertRefreshToken: func(userID UserID) (TokenID, error) {
			if userID != "1" {
				t.Error("unexpected userID in InsertRefreshToken")
			}
			return "456", nil
		},
		MockUpdateRefreshToken: func(info RefreshTokenInfo) error {
			if info.ID != "123" || info.UserID != "1" || !info.Invoked || info.Successor != "456" {
				t.Fatalf("unexpected info in UpdateRefreshToken: %v", info)
			}
			return nil
		},
	}
	handler := RefreshUser(mock)

	token, err := createJWT(createRefreshClaims("1", "123"))
	if err != nil {
		t.Error("unable to create token")
	}
	w := httptest.NewRecorder()
	jsonStr := []byte(fmt.Sprintf(`{"refresh_token":"%s"}`, token))
	req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	result := &TokenResponse{}
	if err := json.Unmarshal(body, result); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if result.UserID != "1" || result.AccessToken == "" || result.RefreshToken == "" {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRefreshUserInvalidToken(t *testing.T) {
	mock := &mockProvider{MockT: t}
	handler := RefreshUser(mock)

	// intentionally using an access token instead of a refresh token
	token, err := createAccessToken(UserInfo{ID: UserID("1"), Email: "user@example.com"})
	if err != nil {
		t.Error("unable to create token")
	}
	w := httptest.NewRecorder()
	jsonStr := []byte(fmt.Sprintf(`{"refresh_token":"%s"}`, token))
	req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	result := &ErrorResponse{}
	if err := json.Unmarshal(body, result); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if !strings.HasPrefix(result.Error, "attempted to invoke an invalid refresh token") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRefreshUserUnknownTokenID(t *testing.T) {
	mock := &mockProvider{
		MockT: t,
		MockGetUserByID: func(userID UserID) (*UserInfo, error) {
			if userID != "1" {
				t.Error("unexpected userID in GetUserByID")
			}
			return &UserInfo{ID: userID, Email: "user@example.com"}, nil
		},
		MockGetRefreshToken: func(tokenID TokenID) (*RefreshTokenInfo, error) {
			if tokenID != "123" {
				t.Error("unexpected tokenID in GetRefreshToken")
			}
			return nil, MissingRecordError{}
		},
		MockInsertRefreshToken: func(userID UserID) (TokenID, error) {
			if userID != "1" {
				t.Error("unexpected userID in InsertRefreshToken")
			}
			return "456", nil
		},
		MockUpdateRefreshToken: func(info RefreshTokenInfo) error {
			if info.ID != "123" || info.UserID != "1" || !info.Invoked || info.Successor != "456" {
				t.Fatalf("unexpected info in UpdateRefreshToken: %v", info)
			}
			return nil
		},
	}
	handler := RefreshUser(mock)

	token, err := createJWT(createRefreshClaims(UserID("1"), TokenID("123")))
	if err != nil {
		t.Error("unable to create token")
	}
	w := httptest.NewRecorder()
	jsonStr := []byte(fmt.Sprintf(`{"refresh_token":"%s"}`, token))
	req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	result := &ErrorResponse{}
	if err := json.Unmarshal(body, result); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if !strings.HasPrefix(result.Error, "attempted to invoke an invalid refresh token") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRefreshUserInvokedToken(t *testing.T) {
	mock := &mockProvider{
		MockT: t,
		MockGetUserByID: func(userID UserID) (*UserInfo, error) {
			if userID != "1" {
				t.Error("unexpected userID in GetUserByID")
			}
			return &UserInfo{ID: userID, Email: "user@example.com"}, nil
		},
		MockDeleteRefreshToken: func(tokenID TokenID) (*RefreshTokenInfo, error) {
			if tokenID == "123" {
				return &RefreshTokenInfo{ID: TokenID("123"), UserID: UserID("1"), Invoked: true, Successor: "456"}, nil
			} else if tokenID == "456" {
				return &RefreshTokenInfo{ID: TokenID("456"), UserID: UserID("1"), Invoked: false}, nil
			} else {
				t.Fatal("unexpected tokenID in DeleteRefreshToken")
				return nil, nil
			}
		},
		MockGetRefreshToken: func(tokenID TokenID) (*RefreshTokenInfo, error) {
			if tokenID != "123" {
				t.Error("unexpected tokenID in GetRefreshToken")
			}
			return &RefreshTokenInfo{ID: TokenID("123"), UserID: UserID("1"), Invoked: true}, nil
		},
		MockInsertRefreshToken: func(userID UserID) (TokenID, error) {
			if userID != "1" {
				t.Error("unexpected userID in InsertRefreshToken")
			}
			return "456", nil
		},
		MockUpdateRefreshToken: func(info RefreshTokenInfo) error {
			if info.ID != "123" || info.UserID != "1" || !info.Invoked || info.Successor != "456" {
				t.Fatalf("unexpected info in UpdateRefreshToken: %v", info)
			}
			return nil
		},
	}
	handler := RefreshUser(mock)

	token, err := createJWT(createRefreshClaims(UserID("1"), TokenID("123")))
	if err != nil {
		t.Error("unable to create token")
	}
	w := httptest.NewRecorder()
	jsonStr := []byte(fmt.Sprintf(`{"refresh_token":"%s"}`, token))
	req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	result := &ErrorResponse{}
	if err := json.Unmarshal(body, result); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if !strings.HasPrefix(result.Error, "attempted to reinvoke a previously invoked refresh token") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRefreshUserMismatchedUser(t *testing.T) {
	mock := &mockProvider{
		MockT: t,
		MockGetUserByID: func(userID UserID) (*UserInfo, error) {
			if userID != "1" {
				t.Error("unexpected userID in GetUserByID")
			}
			return &UserInfo{ID: userID, Email: "user@example.com"}, nil
		},
		MockGetRefreshToken: func(tokenID TokenID) (*RefreshTokenInfo, error) {
			if tokenID != "123" {
				t.Error("unexpected tokenID in GetRefreshToken")
			}
			return &RefreshTokenInfo{ID: TokenID("123"), UserID: UserID("4"), Invoked: false}, nil
		},
		MockInsertRefreshToken: func(userID UserID) (TokenID, error) {
			if userID != "1" {
				t.Error("unexpected userID in InsertRefreshToken")
			}
			return "456", nil
		},
		MockUpdateRefreshToken: func(info RefreshTokenInfo) error {
			if info.ID != "123" || info.UserID != "1" || !info.Invoked || info.Successor != "456" {
				t.Fatalf("unexpected info in UpdateRefreshToken: %v", info)
			}
			return nil
		},
	}
	handler := RefreshUser(mock)

	token, err := createJWT(createRefreshClaims("1", "123"))
	if err != nil {
		t.Error("unable to create token")
	}
	w := httptest.NewRecorder()
	jsonStr := []byte(fmt.Sprintf(`{"refresh_token":"%s"}`, token))
	req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	result := &ErrorResponse{}
	if err := json.Unmarshal(body, result); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if result.Error != "Internal Server Error" {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRefreshUserUpdateFailure(t *testing.T) {
	mock := &mockProvider{
		MockT: t,
		MockGetUserByID: func(userID UserID) (*UserInfo, error) {
			if userID != "1" {
				t.Error("unexpected userID in GetUserByID")
			}
			return &UserInfo{ID: userID, Email: "user@example.com"}, nil
		},
		MockGetRefreshToken: func(tokenID TokenID) (*RefreshTokenInfo, error) {
			if tokenID != "123" {
				t.Error("unexpected tokenID in GetRefreshToken")
			}
			return &RefreshTokenInfo{ID: TokenID("123"), UserID: UserID("1"), Invoked: false}, nil
		},
		MockInsertRefreshToken: func(userID UserID) (TokenID, error) {
			if userID != "1" {
				t.Error("unexpected userID in InsertRefreshToken")
			}
			return "456", nil
		},
		MockUpdateRefreshToken: func(info RefreshTokenInfo) error {
			if info.ID != "123" || info.UserID != "1" || !info.Invoked || info.Successor != "456" {
				t.Fatalf("unexpected info in UpdateRefreshToken: %v", info)
			}
			return fmt.Errorf("failed to updated refresh token")
		},
	}
	handler := RefreshUser(mock)

	token, err := createJWT(createRefreshClaims("1", "123"))
	if err != nil {
		t.Error("unable to create token")
	}
	w := httptest.NewRecorder()
	jsonStr := []byte(fmt.Sprintf(`{"refresh_token":"%s"}`, token))
	req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	result := &ErrorResponse{}
	if err := json.Unmarshal(body, result); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if result.Error != "Internal Server Error" {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRefreshUserInsertFailure(t *testing.T) {
	mock := &mockProvider{
		MockT: t,
		MockGetUserByID: func(userID UserID) (*UserInfo, error) {
			if userID != "1" {
				t.Error("unexpected userID in GetUserByID")
			}
			return &UserInfo{ID: userID, Email: "user@example.com"}, nil
		},
		MockGetRefreshToken: func(tokenID TokenID) (*RefreshTokenInfo, error) {
			if tokenID != "123" {
				t.Error("unexpected tokenID in GetRefreshToken")
			}
			return &RefreshTokenInfo{ID: TokenID("123"), UserID: UserID("1"), Invoked: false}, nil
		},
		MockInsertRefreshToken: func(userID UserID) (TokenID, error) {
			if userID != "1" {
				t.Error("unexpected userID in InsertRefreshToken")
			}
			return "", fmt.Errorf("failed to insert new refresh token")
		},
		MockUpdateRefreshToken: func(info RefreshTokenInfo) error {
			if info.ID != "123" || info.UserID != "1" || !info.Invoked || info.Successor != "456" {
				t.Fatalf("unexpected info in UpdateRefreshToken: %v", info)
			}
			return nil
		},
	}
	handler := RefreshUser(mock)

	token, err := createJWT(createRefreshClaims("1", "123"))
	if err != nil {
		t.Error("unable to create token")
	}
	w := httptest.NewRecorder()
	jsonStr := []byte(fmt.Sprintf(`{"refresh_token":"%s"}`, token))
	req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	result := &ErrorResponse{}
	if err := json.Unmarshal(body, result); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if result.Error != "Internal Server Error" {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRefreshUserInvalidUser(t *testing.T) {
	mock := &mockProvider{
		MockT: t,
		MockGetUserByID: func(userID UserID) (*UserInfo, error) {
			return nil, fmt.Errorf("invalid user error")
		},
		MockGetRefreshToken: func(tokenID TokenID) (*RefreshTokenInfo, error) {
			if tokenID != "123" {
				t.Error("unexpected tokenID in GetRefreshToken")
			}
			return &RefreshTokenInfo{ID: TokenID("123"), UserID: UserID("1"), Invoked: false}, nil
		},
		MockInsertRefreshToken: func(userID UserID) (TokenID, error) {
			if userID != "1" {
				t.Error("unexpected userID in InsertRefreshToken")
			}
			return "456", nil
		},
		MockUpdateRefreshToken: func(info RefreshTokenInfo) error {
			if info.ID != "123" || info.UserID != "1" || !info.Invoked || info.Successor != "456" {
				t.Fatalf("unexpected info in UpdateRefreshToken: %v", info)
			}
			return nil
		},
	}
	handler := RefreshUser(mock)

	token, err := createJWT(createRefreshClaims(UserID("1"), TokenID("123")))
	if err != nil {
		t.Error("unable to create token")
	}
	w := httptest.NewRecorder()
	jsonStr := []byte(fmt.Sprintf(`{"refresh_token":"%s"}`, token))
	req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	result := &ErrorResponse{}
	if err := json.Unmarshal(body, result); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if !strings.HasPrefix(result.Error, "Internal Server Error") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRefreshUserBadJson(t *testing.T) {
	mock := &mockProvider{
		MockT: t,
	}
	handler := RefreshUser(mock)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"bad":"json"}`)
	req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
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

	if !strings.Contains(jsonerr.Error, "Request body contains unknown field") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRegisterUserSuccess(t *testing.T) {
	mock := &mockProvider{MockInsertUser: func(string, string) error { return nil }}
	handler := RegisterUser(mock)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"abcDEF123@example.com", "password": "abdDEF123"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("unexpected response code received: %d ", w.Code)
	}

	if !strings.Contains(w.Result().Header.Get("Content-Type"), "application/json") {
		t.Error("unexpected content type received:", w.Result().Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(w.Result().Body)
	creds := &Credentials{}
	if err := json.Unmarshal(body, creds); err != nil {
		t.Error("unexpected json parsing error: ", err.Error())
	}

	if creds.Email != "abcDEF123@example.com" || creds.Password != "********" {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRegisterUserInvalidUsername(t *testing.T) {
	mock := &mockProvider{MockInsertUser: func(string, string) error { t.Error("mock should not be reached"); return nil }}
	handler := RegisterUser(mock)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"short", "password": "abdDEF123"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
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

	if !strings.Contains(jsonerr.Error, "invalid email") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRegisterUserInvalidPassword(t *testing.T) {
	mock := &mockProvider{MockInsertUser: func(string, string) error { t.Error("mock should not be reached"); return nil }}
	handler := RegisterUser(mock)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"abcDEF123@example.com", "password": "short"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
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

	if !strings.Contains(jsonerr.Error, "invalid password") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRegisterUserInsertFailure(t *testing.T) {
	mock := &mockProvider{MockInsertUser: func(string, string) error { return fmt.Errorf("database insertion failure") }}
	handler := RegisterUser(mock)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"abcDEF123@example.com", "password": "abcDEF123"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
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

	if !strings.Contains(jsonerr.Error, "database insertion failure") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}

func TestRegisterUserBadJson(t *testing.T) {
	mock := &mockProvider{MockInsertUser: func(string, string) error { t.Error("mock should not be reached"); return nil }}
	handler := RegisterUser(mock)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"bad":"json"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
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

	if !strings.Contains(jsonerr.Error, "Request body contains unknown field") {
		t.Errorf("unexpected body in response: %s", string(body))
	}
}
