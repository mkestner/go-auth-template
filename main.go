package main

import (
	"context"
	"log"
	"net/http"
	"os"
)

func main() {
	// Connect to the database
	db, err := connectMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Disconnect(context.TODO())

	router := CreateRouter(mongoDBProvider{database: db.Database(os.Getenv("DB_NAME"))})
	log.Fatal(http.ListenAndServe(":8080", router))
}
