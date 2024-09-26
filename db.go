package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func connectWithRetry(opts *options.ClientOptions) *mongo.Client {
	retries := 0
	connected := false
	for !connected && retries < 5 {
		// Create a new client and connect to the server
		client, err := mongo.Connect(context.TODO(), opts)
		if err != nil {
			slog.Error("unable to connect to mongo", slog.Int("retry_count", retries), slog.String("error", err.Error()))
			retries++
			time.Sleep(5 * time.Second)
		} else {
			slog.Info("successful connection to mongo cluster", slog.Int("retry_count", retries))
			return client
		}
	}
	slog.Error("connection retry limit exceeded")
	return nil
}

func connectMongoDB() (*mongo.Client, error) {
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	url := os.Getenv("DB_URL")
	if url == "" {
		panic("DB_URL must be set on the environment")
	}
	opts := options.Client().ApplyURI(url).SetServerAPIOptions(serverAPI)
	client := connectWithRetry(opts)
	if client == nil {
		panic("unable to connect to mongo")
	}

	// Send a ping to confirm a successful connection
	if err := client.Database("admin").RunCommand(context.TODO(), bson.D{{Key: "ping", Value: 1}}).Err(); err != nil {
		slog.Error("error pinging MongoDB cluster", slog.String("error", err.Error()))
		return nil, err
	}
	slog.Info("successfully connected to MongoDB")
	return client, nil 
}

