package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwk"
)

type AuthClient struct {
	baseUrl      string
	realm        string
	jwksInterval int
	jwks         jwk.Set
}

func NewAuthClient(baseUrl string, realm string, jwksInterval int) (*AuthClient, error) {
	client := &AuthClient{baseUrl: baseUrl, realm: realm, jwksInterval: jwksInterval}

	if err := client.FetchAndUpdateJWKS(); err != nil {
		return nil, err
	}

	go client.PeriodicallyFetchJWKS()

	return client, nil
}

func (c *AuthClient) FetchAndUpdateJWKS() error {
	jwksUrl := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.baseUrl, c.realm)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, jwksUrl, nil)
	if err != nil {
		return err
	}

	set, err := jwk.Fetch(req.Context(), jwksUrl)
	if err != nil {
		return err
	}

	c.jwks = set
	log.Println("JWKS updated successfully")
	return nil
}

func (c *AuthClient) PeriodicallyFetchJWKS() {
	ticker := time.NewTicker(time.Duration(c.jwksInterval) * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if err := c.FetchAndUpdateJWKS(); err != nil {
			log.Printf("Error fetching JWKS: %v", err)
		}
	}
}

func (c *AuthClient) ValidateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("invalid token header")
		}
		key, ok := c.jwks.LookupKeyID(kid)
		if !ok {
			return nil, errors.New("key not found")
		}

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, errors.New("failed to extract key")
		}

		return rawKey, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return token, nil
}

func (c *AuthClient) ParseToken(tokenString string) (*User, error) {
	token, err := c.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unable to parse token claims")
	}

	userID, err := uuid.Parse(claims["sub"].(string))
	if err != nil {
		return nil, errors.New("invalid user ID in token")
	}

	userDetails := &User{
		ID:        userID,
		Username:  claims["preferred_username"].(string),
		FirstName: claims["given_name"].(string),
		LastName:  claims["family_name"].(string),
		Email:     claims["email"].(string),
	}

	return userDetails, nil
}
