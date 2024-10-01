package main

import (
	"go-auth-template/auth"
	"log"
	"net/http"
)

// CreateRouter constructs a new Mux with route handlers attached
func CreateRouter(db auth.Provider) *http.ServeMux {
	router := http.NewServeMux()

	// setup the auth module route handlers
	router.HandleFunc("POST /auth/register", auth.RegisterUser(db))
	router.HandleFunc("POST /auth/login", auth.LoginUser(db))
	router.HandleFunc("POST /auth/refresh", auth.RefreshUser(db))

	// set up a protected route handler using the Middleware proxy
	router.HandleFunc("GET /protected", auth.Middleware(protected()))

	return router
}

// Simple route handler that pulls the user information out of the context
// and returns 200. Demonstrates the auth module middleware.
func protected() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// pull the user information out of the context
		user := auth.GetUser(r.Context())
		log.Print("/protected route reached: ", user)

		// return 200
		w.WriteHeader(http.StatusOK)
	})
}
