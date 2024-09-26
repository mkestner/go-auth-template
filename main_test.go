package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go-auth-template/auth"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/mongo"
)

type IntegrationTestSuite struct {
	suite.Suite
	router   *http.ServeMux
	client   *mongo.Client
	provider auth.Provider
}

const testPassword string = "abcDEF123"

func (s *IntegrationTestSuite) SetupSuite() {
	client, err := connectMongoDB()
	s.NoError(err)

	db := mongoDBProvider{database: client.Database(os.Getenv("DB_NAME"))}
	s.router = CreateRouter(db)
	s.provider = db
	s.client = client
}

func (s *IntegrationTestSuite) TearDownSuite() {
	s.client.Disconnect(context.TODO())
}

func (s *IntegrationTestSuite) TestRegisterUserSuccess() {
	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"RegisterUserSuccess@example.com", "password": "abdDEF123"}`)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/auth/register", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusCreated, w.Code)

	s.Contains(w.Result().Header.Get("Content-Type"), "application/json")

	body, _ := io.ReadAll(w.Result().Body)
	creds := &auth.Credentials{}
	err := json.Unmarshal(body, creds)
	s.NoError(err)

	s.Equal("RegisterUserSuccess@example.com", creds.Email)
	s.Equal("********", creds.Password)
}

func (s *IntegrationTestSuite) TestRegisterUserInvalidEmail() {
	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"notanemailaddr", "password": "abdDEF123"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusBadRequest, w.Code)
	s.Contains(w.Result().Header.Get("Content-Type"), "application/json")

	body, _ := io.ReadAll(w.Result().Body)
	jsonerr := &auth.ErrorResponse{}
	err := json.Unmarshal(body, jsonerr)
	s.NoError(err)

	s.Contains(jsonerr.Error, "invalid email")
}

func (s *IntegrationTestSuite) TestRegisterUserBadJson() {
	w := httptest.NewRecorder()
	jsonStr := []byte(`{"bad":"json"}`)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusBadRequest, w.Code)
	s.Contains(w.Result().Header.Get("Content-Type"), "application/json")

	body, _ := io.ReadAll(w.Result().Body)
	jsonerr := &auth.ErrorResponse{}
	err := json.Unmarshal(body, jsonerr)
	s.NoError(err)

	s.Contains(jsonerr.Error, "Request body contains unknown field")
}

func (s *IntegrationTestSuite) TestLoginUserSuccess() {
	s.provider.InsertUser("LoginUserSuccess@example.com", testPassword)
	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"LoginUserSuccess@example.com", "password": "` + testPassword + `"}`)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/auth/login", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusOK, w.Code)
	s.Contains(w.Result().Header.Get("Content-Type"), "application/json")

	body, _ := io.ReadAll(w.Result().Body)
	tokenResponse := &auth.TokenResponse{}
	err := json.Unmarshal(body, tokenResponse)
	s.NoError(err)
	s.NotEmpty(tokenResponse.UserID)
	s.NotEmpty(tokenResponse.AccessToken)
	s.NotEmpty(tokenResponse.RefreshToken)
}

func (s *IntegrationTestSuite) TestLoginUserBadJson() {
	w := httptest.NewRecorder()
	jsonStr := []byte(`{"bad":"json"}`)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/auth/login", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusBadRequest, w.Code)
	s.Contains(w.Result().Header.Get("Content-Type"), "application/json")

	body, _ := io.ReadAll(w.Result().Body)
	jsonerr := &auth.ErrorResponse{}
	err := json.Unmarshal(body, jsonerr)
	s.NoError(err)
	s.Contains(jsonerr.Error, "Request body contains unknown field")
}

func (s *IntegrationTestSuite) TestLoginUserUnknownEmail() {
	w := httptest.NewRecorder()
	jsonStr := []byte(`{"email":"unknown@example.com", "password": "abdDEF123"}`)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusBadRequest, w.Code)
	s.Contains(w.Result().Header.Get("Content-Type"), "application/json")

	body, _ := io.ReadAll(w.Result().Body)
	jsonerr := &auth.ErrorResponse{}
	err := json.Unmarshal(body, jsonerr)
	s.NoError(err)

	s.Contains(jsonerr.Error, "unknown email")
}

func (s *IntegrationTestSuite) getTokens(email string) (*auth.TokenResponse, error) {
	w := httptest.NewRecorder()
	creds := auth.Credentials{Email: email, Password: testPassword}
	jsonStr, err := json.Marshal(creds)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/auth/login", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		return nil, fmt.Errorf("login failed")
	}
	body, _ := io.ReadAll(w.Result().Body)
	tokenResponse := &auth.TokenResponse{}
	err = json.Unmarshal(body, tokenResponse)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}
func (s *IntegrationTestSuite) TestRefreshUserSuccess() {
	email := "RefreshUserSuccess@example.com"
	err := s.provider.InsertUser(email, testPassword)
	s.NoError(err)
	tokens, err := s.getTokens(email)
	s.NoError(err)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"refresh_token":"` + tokens.RefreshToken + `"}`)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusOK, w.Code)
	s.Contains(w.Result().Header.Get("Content-Type"), "application/json")

	body, _ := io.ReadAll(w.Result().Body)
	tokenResponse := &auth.TokenResponse{}
	err = json.Unmarshal(body, tokenResponse)
	s.NoError(err)
	s.Equal(tokens.UserID, tokenResponse.UserID)
	s.NotEmpty(tokenResponse.AccessToken)
	s.NotEmpty(tokenResponse.RefreshToken)
}

func (s *IntegrationTestSuite) TestRefreshUserReinvoke() {
	email := "RefreshUserReinvoke@example.com"
	err := s.provider.InsertUser(email, testPassword)
	s.NoError(err)
	tokens, err := s.getTokens(email)
	s.NoError(err)

	// Invoke
	w := httptest.NewRecorder()
	jsonStr := []byte(`{"refresh_token":"` + tokens.RefreshToken + `"}`)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)
	s.Equal(http.StatusOK, w.Code)

	// Invoke same refresh token again
	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(context.Background(), "POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusBadRequest, w.Code)
	s.Contains(w.Result().Header.Get("Content-Type"), "application/json")

	body, _ := io.ReadAll(w.Result().Body)
	response := &auth.ErrorResponse{}
	err = json.Unmarshal(body, response)
	s.NoError(err)
	s.Equal("attempted to reinvoke a previously invoked refresh token.", response.Error)
}

func (s *IntegrationTestSuite) TestRefreshUserInvokePurgedToken() {
	email := "RefreshUserInvokePurgedToken@example.com"
	err := s.provider.InsertUser(email, testPassword)
	s.NoError(err)
	tokens, err := s.getTokens(email)
	s.NoError(err)

	// Invoke refresh token
	w := httptest.NewRecorder()
	jsonStr := []byte(`{"refresh_token":"` + tokens.RefreshToken + `"}`)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)
	s.Equal(http.StatusOK, w.Code)
	body, _ := io.ReadAll(w.Result().Body)
	tokenResponse := &auth.TokenResponse{}
	err = json.Unmarshal(body, tokenResponse)
	s.NoError(err)

	// reinvoke initial refresh token.  This purges tokens.RefreshToken and tokenResponse.RefreshToken as they are chained
	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(context.Background(), "POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	s.router.ServeHTTP(w, req)
	s.Equal(http.StatusBadRequest, w.Code)

	// Invoke the refresh token returned by the first refresh
	w = httptest.NewRecorder()
	jsonStr = []byte(`{"refresh_token":"` + tokenResponse.RefreshToken + `"}`)
	req, _ = http.NewRequestWithContext(context.Background(), "POST", "/auth/refresh", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusBadRequest, w.Code)
	s.Contains(w.Result().Header.Get("Content-Type"), "application/json")

	body, _ = io.ReadAll(w.Result().Body)
	response := &auth.ErrorResponse{}
	err = json.Unmarshal(body, response)
	s.NoError(err)
	s.Equal("attempted to invoke an invalid refresh token: token record missing", response.Error)
}

func (s *IntegrationTestSuite) TestProtectedSuccess() {
	email := "ProtectedSuccess@example.com"
	err := s.provider.InsertUser(email, testPassword)
	s.NoError(err)
	tokens, err := s.getTokens(email)
	s.NoError(err)

	w := httptest.NewRecorder()
	jsonStr := []byte(`{"account_name":"Checking"}`)
	req, _ := http.NewRequest("GET", "/protected", bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusOK, w.Code)
}

func (s *IntegrationTestSuite) TestProtectedMissingToken() {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)

	s.router.ServeHTTP(w, req)

	s.Equal(http.StatusUnauthorized, w.Code)
	s.Contains(w.Result().Header.Get("Content-Type"), "application/json")

	body, _ := io.ReadAll(w.Result().Body)
	jsonResponse := &auth.ErrorResponse{}
	s.NoError(json.Unmarshal(body, jsonResponse))

	s.Contains(jsonResponse.Error, "Authorization header missing or lacks 'Bearer ' prefix")
}

func TestIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	suite.Run(t, new(IntegrationTestSuite))
}
