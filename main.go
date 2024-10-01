package main

import (
	"context"
	"log"
	"net/http"
	"os"
)

func main() {
	// Connect to the database
	client, err := connectMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.TODO())

	db := client.Database(os.Getenv("DB_NAME"))
	provider := mongoDBProvider{database: db}

	router := CreateRouter(provider)
	log.Fatal(http.ListenAndServe(":8080", router))
}
