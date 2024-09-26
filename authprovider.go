package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"go-auth-template/auth"
	"log/slog"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type mongoDBProvider struct {
	database *mongo.Database
}

type userDoc struct {
	ID             primitive.ObjectID `bson:"_id"`
	Email          string             `bson:"email"`
	HashedPassword string             `bson:"hashed_password"`
}

type tokenDoc struct {
	ID        primitive.ObjectID `bson:"_id"`
	UserID    primitive.ObjectID `bson:"user_id"`
	Successor primitive.ObjectID `bson:"successor"`
	Invoked   bool               `bson:"invoked"`
}

func (doc tokenDoc) toInfo() auth.RefreshTokenInfo {
	return auth.RefreshTokenInfo{
		ID:        auth.TokenID(doc.ID.Hex()),
		UserID:    auth.UserID(doc.UserID.Hex()),
		Invoked:   doc.Invoked,
		Successor: auth.TokenID(doc.Successor.Hex()),
	}
}

func (m mongoDBProvider) GetUser(email string) (*auth.UserInfo, error) {
	var user userDoc
	collection := m.database.Collection("users")
	err := collection.FindOne(context.TODO(), bson.D{{Key: "email", Value: email}}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			slog.Error("missing user document in get user", slog.String("email", email))
			return nil, auth.MissingRecordError{}
		}
		slog.Error("error while finding user", slog.String("email", email), slog.String("error", err.Error()))
		return nil, err
	}
	hashedPassword, err := base64.StdEncoding.DecodeString(user.HashedPassword)
	if err != nil {
		slog.Error("error decoding password from base64", slog.String("error", err.Error()))
		return nil, fmt.Errorf("error decoding base64 encoded password: %s", err.Error())
	}
	return &auth.UserInfo{ID: auth.UserID(user.ID.Hex()), Email: user.Email, HashedPassword: hashedPassword}, nil
}

func (m mongoDBProvider) GetUserByID(userID auth.UserID) (*auth.UserInfo, error) {
	coll := m.database.Collection("users")
	id, _ := primitive.ObjectIDFromHex(string(userID))
	filter := bson.D{{Key: "_id", Value: id}}
	var doc userDoc
	err := coll.FindOne(context.TODO(), filter).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			slog.Error("missing user", slog.String("userid", string(userID)))
			return nil, auth.MissingRecordError{}
		}
		slog.Error("error while finding user doc", slog.String("userid", string(userID)), slog.String("error", err.Error()))
		return nil, err
	}
	result := auth.UserInfo{ID: userID, Email: doc.Email}
	return &result, nil
}

func (m mongoDBProvider) InsertUser(email string, password string) error {
	var existingUser userDoc
	collection := m.database.Collection("users")
	err := collection.FindOne(context.TODO(), bson.D{{Key: "email", Value: email}}).Decode(&existingUser)
	if err == nil {
		slog.Warn("attempt to register existing user", slog.String("email", email))
		return auth.DuplicateUserError{}
	}
	if err != mongo.ErrNoDocuments {
		slog.Error("error fetching user record", slog.String("email", email), slog.String("error", err.Error()))
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("failure hashing password", slog.String("error", err.Error()))
		return err
	}

	user := &userDoc{
		ID:             primitive.NewObjectID(),
		Email:          email,
		HashedPassword: base64.StdEncoding.EncodeToString(hashedPassword),
	}

	_, err = collection.InsertOne(context.TODO(), user)
	if err != nil {
		slog.Error("error inserting user doc", slog.String("email", email), slog.String("error", err.Error()))
		return err
	}
	return nil
}

func (m mongoDBProvider) CreateRefreshToken(userID auth.UserID) (string, error) {
	userOID, err := primitive.ObjectIDFromHex(string(userID))
	if err != nil {
		slog.Error("unable to convert userID", slog.String("userID", string(userID)), slog.String("error", err.Error()))
		return "", auth.InvalidParameterError{Parameter: "userID"}
	}
	doc := &tokenDoc{
		ID:     primitive.NewObjectID(),
		UserID: userOID,
	}
	collection := m.database.Collection("tokens")
	_, err = collection.InsertOne(context.TODO(), doc)
	if err != nil {
		slog.Error("error inserting token doc", slog.String("user_id", string(userID)), slog.String("error", err.Error()))
		return "", err
	}
	return doc.ID.Hex(), nil
}

func (m mongoDBProvider) DeleteRefreshToken(tokenID auth.TokenID) (*auth.RefreshTokenInfo, error) {
	collection := m.database.Collection("tokens")
	id, err := primitive.ObjectIDFromHex(string(tokenID))
	if err != nil {
		return nil, auth.InvalidParameterError{Parameter: "token_id"}
	}

	var doc tokenDoc
	err = collection.FindOneAndDelete(context.TODO(), bson.D{{Key: "_id", Value: id}}).Decode(&doc)
	if err != nil {
		slog.Error("error fetching token record", slog.String("token_id", string(tokenID)), slog.String("error", err.Error()))
		return nil, err
	}

	info := doc.toInfo()
	return &info, nil
}

func (m mongoDBProvider) GetRefreshToken(tokenID auth.TokenID) (*auth.RefreshTokenInfo, error) {
	tokenOID, err := primitive.ObjectIDFromHex(string(tokenID))
	if err != nil {
		slog.Error("unable to convert tokenID", slog.String("tokenID", string(tokenID)), slog.String("error", err.Error()))
		return nil, auth.InvalidParameterError{Parameter: "token_id"}
	}
	var doc tokenDoc
	collection := m.database.Collection("tokens")
	filter := bson.D{{Key: "_id", Value: tokenOID}}
	err = collection.FindOne(context.TODO(), filter).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			slog.Error("missing token record", slog.String("token_id", string(tokenID)))
			return nil, auth.MissingRecordError{}
		}
		slog.Error("error fetching token record", slog.String("token_id", string(tokenID)), slog.String("error", err.Error()))
		return nil, err
	}
	info := doc.toInfo()
	return &info, nil
}

func (m mongoDBProvider) InsertRefreshToken(userID auth.UserID) (auth.TokenID, error) {
	collection := m.database.Collection("tokens")
	uid, err := primitive.ObjectIDFromHex(string(userID))
	if err != nil {
		slog.Error("unable to convert userID", slog.String("user_id", string(userID)), slog.String("error", err.Error()))
		return "", auth.InvalidParameterError{Parameter: "userID"}
	}
	doc := &tokenDoc{
		ID:     primitive.NewObjectID(),
		UserID: uid,
	}
	_, err = collection.InsertOne(context.TODO(), doc)
	if err != nil {
		slog.Error("error inserting token doc", slog.String("user_id", string(userID)), slog.String("error", err.Error()))
		return "", err
	}

	return auth.TokenID(doc.ID.Hex()), nil
}

func (m mongoDBProvider) UpdateRefreshToken(info auth.RefreshTokenInfo) error {
	uid, err := primitive.ObjectIDFromHex(string(info.UserID))
	if err != nil {
		slog.Error("unable to convert userID", slog.String("user_id", string(info.UserID)), slog.String("error", err.Error()))
		return auth.InvalidParameterError{Parameter: "userID"}
	}
	tid, err := primitive.ObjectIDFromHex(string(info.ID))
	if err != nil {
		slog.Error("unable to convert tokenID", slog.String("token_id", string(info.ID)), slog.String("error", err.Error()))
		return auth.InvalidParameterError{Parameter: "tokenID"}
	}
	sid, err := primitive.ObjectIDFromHex(string(info.Successor))
	if err != nil {
		slog.Error("unable to convert successor", slog.String("successor", string(info.Successor)), slog.String("error", err.Error()))
		return auth.InvalidParameterError{Parameter: "successor"}
	}
	collection := m.database.Collection("tokens")
	doc := tokenDoc{
		ID:        tid,
		UserID:    uid,
		Invoked:   info.Invoked,
		Successor: sid,
	}

	filter := bson.D{{Key: "_id", Value: tid}}
	_, err = collection.ReplaceOne(context.TODO(), filter, doc)
	if err != nil {
		slog.Error("error updating token record", slog.String("token_id", string(info.ID)), slog.String("error", err.Error()))
		return err
	}
	return nil
}
