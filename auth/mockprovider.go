package auth

import "testing"

type mockProvider struct {
	MockT                  *testing.T
	MockGetUser            func(username string) (*UserInfo, error)
	MockGetUserByID        func(userID UserID) (*UserInfo, error)
	MockInsertUser         func(username string, hashedPassword string) error
	MockDeleteRefreshToken func(tokenID TokenID) (*RefreshTokenInfo, error)
	MockGetRefreshToken    func(tokenID TokenID) (*RefreshTokenInfo, error)
	MockInsertRefreshToken func(userID UserID) (TokenID, error)
	MockUpdateRefreshToken func(tokenInfo RefreshTokenInfo) error
}

func (m mockProvider) GetUser(email string) (*UserInfo, error) {
	if m.MockGetUser != nil {
		return m.MockGetUser(email)
	}
	m.MockT.Fatal("unexpected invocation of GetUser")
	return nil, nil
}

func (m mockProvider) GetUserByID(userID UserID) (*UserInfo, error) {
	if m.MockGetUserByID != nil {
		return m.MockGetUserByID(userID)
	}
	m.MockT.Fatal("unexpected invocation of GetUserByID")
	return nil, nil
}

func (m mockProvider) InsertUser(email string, hashedPassword string) error {
	if m.MockInsertUser != nil {
		return m.MockInsertUser(email, hashedPassword)
	}
	m.MockT.Fatal("unexpected invocation of InsertUser")
	return nil
}

func (m mockProvider) DeleteRefreshToken(tokenID TokenID) (*RefreshTokenInfo, error) {
	if m.MockDeleteRefreshToken != nil {
		return m.MockDeleteRefreshToken(tokenID)
	}
	m.MockT.Fatal("unexpected invocation of DeleteRefreshToken")
	return nil, nil
}

func (m mockProvider) GetRefreshToken(tokenID TokenID) (*RefreshTokenInfo, error) {
	if m.MockGetRefreshToken != nil {
		return m.MockGetRefreshToken(tokenID)
	}
	m.MockT.Fatal("unexpected invocation of GetRefreshToken")
	return nil, nil
}

func (m mockProvider) InsertRefreshToken(userID UserID) (TokenID, error) {
	if m.MockInsertRefreshToken != nil {
		return m.MockInsertRefreshToken(userID)
	}
	m.MockT.Fatal("unexpected invocation of InsertRefreshToken")
	return "", nil
}

func (m mockProvider) UpdateRefreshToken(tokenInfo RefreshTokenInfo) error {
	if m.MockUpdateRefreshToken != nil {
		return m.MockUpdateRefreshToken(tokenInfo)
	}
	m.MockT.Fatal("unexpected invocation of UpdateRefreshToken")
	return nil
}
