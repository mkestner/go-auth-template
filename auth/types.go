package auth

// Credentials contains user authentication values for register and login requests
type Credentials struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RefreshRequest contains a refresh token for obtaining new tokens
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// ErrorResponse is the json body returned for all errors on the REST interface
type ErrorResponse struct {
	Error string `json:"error"`
}

// TokenResponse is returned in response to successful login requests
type TokenResponse struct {
	UserID       string `json:"user_id" binding:"required"`
	AccessToken  string  `json:"access_token" binding:"required"`
	RefreshToken string  `json:"refresh_token" binding:"required"`
}
