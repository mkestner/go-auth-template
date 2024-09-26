package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type token string

const emptyToken token = ""

type customClaims struct {
	UserID UserID `json:"userid"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type customRefreshClaims struct {
	UserID  UserID  `json:"user_id"`
	TokenID TokenID `json:"token_id"`
	jwt.RegisteredClaims
}

// InvalidTokenError is returned when an attempt to reinvoke a previously invoked refresh token occurs.
type invalidTokenError struct {
	Details string
}

func (f invalidTokenError) Error() string {
	return "attempted to invoke an invalid refresh token: " + f.Details
}

// InvokedTokenError is returned when an attempt to reinvoke a previously invoked refresh token occurs.
type invokedTokenError struct {
}

func (f invokedTokenError) Error() string {
	return "attempted to reinvoke a previously invoked refresh token."
}

func createJWT(claims jwt.Claims) (token, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signed, err := tok.SignedString([]byte(os.Getenv("JWT_SIGNING_KEY")))
	if err != nil {
		return emptyToken, fmt.Errorf("error signing token: %s", err.Error())
	}

	return token(signed), nil
}

func createAccessToken(user UserInfo) (token, error) {
	claims := customClaims{
		user.ID,
		user.Email,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    os.Getenv("JWT_AUTHORITY"),
		},
	}

	return createJWT(claims)
}

func createRefreshClaims(userID UserID, refreshID TokenID) customRefreshClaims {
	return customRefreshClaims{
		userID,
		refreshID,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(90 * 24 * time.Hour)),
			Issuer:    os.Getenv("JWT_AUTHORITY"),
		},
	}
}

func createRefreshToken(provider Provider, userID UserID) (token, error) {
	refreshID, err := provider.InsertRefreshToken(userID)
	if err != nil {
		slog.Error(
			"failed to create refresh token id",
			slog.String("user_id", string(userID)),
			slog.String("error", err.Error()),
		)
		return emptyToken, fmt.Errorf("failed to insert refresh token record")
	}

	claims := createRefreshClaims(userID, refreshID)
	return createJWT(claims)
}

func parseRefreshToken(tokenString string) (*customRefreshClaims, error) {
	token, err := jwt.ParseWithClaims(string(tokenString), &customRefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SIGNING_KEY")), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %s", err.Error())
	}
	claims, ok := token.Claims.(*customRefreshClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("failed to validate refresh token")
	}
	if claims.UserID == "" || claims.TokenID == "" {
		return nil, fmt.Errorf("claims missing in refresh token")
	}
	return claims, nil
}

func invalidateTokenChain(provider Provider, tokenInfo RefreshTokenInfo) {

	for count, tokenID := 0, tokenInfo.ID; tokenID != ""; count++ {
		info, err := provider.DeleteRefreshToken(tokenID)
		if err != nil {
			slog.Error("error deleting record in token chain", slog.String("error", err.Error()))
			return
		}
		tokenID = info.Successor
	}
}

func invokeRefreshToken(provider Provider, token string) (token, UserID, error) {
	claims, err := parseRefreshToken(token)
	if err != nil {
		slog.Warn(
			"failed to parse refresh token",
			slog.String("refresh_token", string(token)),
			slog.String("error", err.Error()),
		)
		return emptyToken, "", invalidTokenError{Details: err.Error()}
	}

	userID := claims.UserID
	tokenInfo, err := provider.GetRefreshToken(claims.TokenID)
	if err != nil {
		slog.Warn(
			"failed to retrieve refresh token info",
			slog.String("refresh_token", string(token)),
			slog.String("error", err.Error()),
		)
		var mre MissingRecordError
		if errors.As(err, &mre) {
			return emptyToken, "", invalidTokenError{Details: "token record missing"}
		}
		return emptyToken, userID, err
	}

	if tokenInfo.UserID != userID {
		slog.Error("mismatch in token claims and token info from provider")
		return emptyToken, userID, fmt.Errorf("inconsistent information found in refresh token")
	}

	if tokenInfo.Invoked {
		slog.Warn("attempt to invoke previously invoked refresh token", slog.String("refresh_token", string(token)))
		invalidateTokenChain(provider, *tokenInfo)
		return emptyToken, userID, invokedTokenError{}
	}

	tokenID, err := provider.InsertRefreshToken(claims.UserID)
	if err != nil {
		slog.Error("unable to insert new refresh token record", slog.String("error", err.Error()))
		return emptyToken, userID, err
	}
	tokenInfo.Successor = tokenID
	tokenInfo.Invoked = true

	err = provider.UpdateRefreshToken(*tokenInfo)
	if err != nil {
		slog.Error("unable to update refresh token record", slog.String("error", err.Error()))
		return emptyToken, userID, err
	}
	newClaims := createRefreshClaims(claims.UserID, tokenID)
	tok, err := createJWT(newClaims)
	return tok, userID, err
}
