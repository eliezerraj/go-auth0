package service

import (
	"context"
	"fmt"
	"github.com/rs/zerolog/log"

	"github.com/go-auth0/internal/lib"
	"github.com/go-auth0/internal/erro"
	"github.com/go-auth0/internal/core"
		
	"github.com/golang-jwt/jwt/v4"
)

var childLogger = log.With().Str("service", "service").Logger()

type WorkerService struct {
	jwtKey	[]byte
}

func NewWorkerService(jwtKey []byte) *WorkerService{
	childLogger.Debug().Msg("NewWorkerService")

	return &WorkerService{
		jwtKey: jwtKey,
	}
}

func (w WorkerService) TokenValidation(ctx context.Context, credential core.Credential) (bool, error){
	childLogger.Debug().Msg("TokenValidation")
	childLogger.Debug().Interface("=> credential : ", credential.Token).Msg("")
	childLogger.Debug().Msg("--------------------------------------")
	childLogger.Debug().Interface("=> w.jwtKey : ", w.jwtKey).Msg("")

	span := lib.Span(ctx, "service.TokenValidation")
	defer span.End()

	// Check with token is signed 
	claims := &core.JwtData{}
	tkn, err := jwt.ParseWithClaims(credential.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return w.jwtKey, nil
	})

	if err != nil {
		fmt.Println(err)
		if err == jwt.ErrSignatureInvalid {
			return false, erro.ErrStatusUnauthorized
		}
		return false, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return false, erro.ErrStatusUnauthorized
	}

	return true ,nil
}