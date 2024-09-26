package auth

import (
	"fmt"
)

// TokenID is a string-based type for token identifiers.
type TokenID string;

// UserID is a string-based type for user identifiers.
type UserID string;

// RefreshTokenInfo is a type used by the Provider to manage token chains and status.
type RefreshTokenInfo struct {
	ID        TokenID
	UserID    UserID
	Invoked   bool
	Successor TokenID
}

// UserInfo contains the stored credentials for a registered user
type UserInfo struct {
	ID             UserID
	Email          string
	HashedPassword []byte
}

// DuplicateUserError is returned when a register occurs for an existing user
type DuplicateUserError struct {
	Email string
}

func (f DuplicateUserError) Error() string {
	return fmt.Sprintf("attempt to register existing email: %s", f.Email)
}

// InvalidParameterError is returned when a parameter contains an invalid value
type InvalidParameterError struct {
	Parameter string
}

func (e InvalidParameterError) Error() string {
	return fmt.Sprintf("invalid value for %s provided", e.Parameter)
}

// MissingRecordError is returned when database lookups fail to find requested records
type MissingRecordError struct {
}

func (f MissingRecordError) Error() string {
	return "unable to retrieve requested record"
}

// Provider is a database provider interface
type Provider interface {
	GetUser(email string) (*UserInfo, error)
	GetUserByID(userID UserID) (*UserInfo, error)
	InsertUser(email string, hashedPassword string) error
	DeleteRefreshToken(tokenID TokenID) (*RefreshTokenInfo, error)
	GetRefreshToken(tokenID TokenID) (*RefreshTokenInfo, error)
	InsertRefreshToken(userID UserID) (TokenID, error)
	UpdateRefreshToken(tokenInfo RefreshTokenInfo) (error)
}
