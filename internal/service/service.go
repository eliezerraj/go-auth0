package service

import (
	"context"
	"fmt"
	"github.com/rs/zerolog/log"
	"time"
	"encoding/base64"
    "encoding/pem"
	"crypto/rsa"
	"crypto/x509"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"github.com/go-auth0/internal/lib"
	"github.com/go-auth0/internal/erro"
	"github.com/go-auth0/internal/core"
	"github.com/go-auth0/internal/config/parameter_store_aws"
	"github.com/go-auth0/internal/config/secret_manager_aws"
	"github.com/go-auth0/internal/repository/dynamo"

	//"github.com/aws/aws-sdk-go-v2/service/ssm"
	//"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	//"github.com/golang-jwt/jwt/v4"
)

var childLogger = log.With().Str("service", "service").Logger()

type WorkerService struct {
	AwsClientSecretManager 	*secret_manager_aws.AwsClientSecretManager
	AwsClientParameterStore *parameter_store_aws.AwsClientParameterStore
	workerDynamo			*dynamo.DynamoRepository
	RSA_Key					*core.RSA_Key
}

func NewWorkerService(	awsClientSecretManager *secret_manager_aws.AwsClientSecretManager, 
						awsClientParameterStore *parameter_store_aws.AwsClientParameterStore,
						workerDynamo	*dynamo.DynamoRepository,
						rsaKey			*core.RSA_Key ) *WorkerService{
	childLogger.Debug().Msg("NewWorkerService")

	return &WorkerService{
		AwsClientSecretManager: awsClientSecretManager,
		AwsClientParameterStore: awsClientParameterStore,
		workerDynamo: 	workerDynamo,
		RSA_Key: rsaKey,
	}
}

func (a WorkerService) OAUTHCredential(ctx context.Context, credential core.Credential) (*core.Authentication, error){
	childLogger.Debug().Msg("OAUTHCredential")

	span := lib.Span(ctx, "service.OAUTHCredential")
	defer span.End()

	_, err := a.workerDynamo.Login(ctx, credential)
	if err != nil {
		return nil, err
	}

	// get scopes associated with a credential
	credential_scope, err := a.workerDynamo.QueryCredentialScope(ctx, credential)
	if err != nil {
		return nil, err
	}

	// Set a JWT expiration date 
	expirationTime := time.Now().Add(720 * time.Minute)

	newUUID := uuid.New()
	uuidString := newUUID.String()

	// Create a JWT Oauth 2.0 with all scopes and expiration date
	jwtData := &core.JwtData{
								Username: credential.User,
								Scope: credential_scope.Scope,
								ISS: "lambda-go-autentication",
								Version: "2",
								JwtId: uuidString,
								TokenUse: "access",
								RegisteredClaims: jwt.RegisteredClaims{
									ExpiresAt: jwt.NewNumericDate(expirationTime), 	// JWT expiry time is unix milliseconds
								},
	}

	// Add the claims and sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtData)
	tokenString, err := token.SignedString(a.RSA_Key.HS256)
	if err != nil {
		return nil, err
	}
	
	auth := core.Authentication{Token: tokenString, 
								ExpirationTime :expirationTime}	

	return &auth ,nil
}

func (w WorkerService) TokenValidation(ctx context.Context, credential core.Credential) (bool, error){
	childLogger.Debug().Msg("TokenValidation")
	childLogger.Debug().Interface("=> credential : ", credential.Token).Msg("")
	childLogger.Debug().Msg("--------------------------------------")

	span := lib.Span(ctx, "service.TokenValidation")
	defer span.End()

	// Check with token is signed 
	claims := &core.JwtData{}
	tkn, err := jwt.ParseWithClaims(credential.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return w.RSA_Key.HS256, nil
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

func (a WorkerService) OAUTHCredentialRSA(ctx context.Context, credential core.Credential) (*core.Authentication, error){
	childLogger.Debug().Msg("OAUTHCredentialRSA")

	span := lib.Span(ctx, "service.OAUTHCredentialRSA")
	defer span.End()

	_, err := a.workerDynamo.Login(ctx, credential)
	if err != nil {
		return nil, err
	}

	// get scopes associated with a credential
	credential_scope, err := a.workerDynamo.QueryCredentialScope(ctx, credential)
	if err != nil {
		return nil, err
	}

	// Set a JWT expiration date 
	expirationTime := time.Now().Add(720 * time.Minute)

	newUUID := uuid.New()
	uuidString := newUUID.String()

	// Create a JWT Oauth 2.0 with all scopes and expiration date
	jwtData := &core.JwtData{
								Username: credential.User,
								Scope: credential_scope.Scope,
								ISS: "lambda-go-autentication",
								Version: "2",
								JwtId: uuidString,
								TokenUse: "access",
								RegisteredClaims: jwt.RegisteredClaims{
									ExpiresAt: jwt.NewNumericDate(expirationTime), 	// JWT expiry time is unix milliseconds
								},
	}

	// Add the claims and sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtData)
	tokenString, err := token.SignedString(a.RSA_Key.PrivateKeyPem)
	if err != nil {
		return nil, err
	}
	
	auth := core.Authentication{Token: tokenString, 
								ExpirationTime :expirationTime}	

	return &auth ,nil
}

func (w WorkerService) TokenValidationRSA(ctx context.Context, jwksData core.JwksData) (bool, error){
	childLogger.Debug().Msg("TokenValidationRSA")
	childLogger.Debug().Interface("=> jwksData : ", jwksData).Msg("")
	childLogger.Debug().Msg("--------------------------------------")

	span := lib.Span(ctx, "service.TokenValidationRSA")
	defer span.End()

	jwksDataRSABytes, err := base64.RawURLEncoding.DecodeString(jwksData.RSAPublicKeyB64)
	if err != nil {
		childLogger.Error().Err(err).Msg("erro RawURLEncoding.DecodeString")
		return false, nil
	}

	fmt.Printf("%s ",string(jwksDataRSABytes))

	var publicKey *rsa.PublicKey
	block, _ := pem.Decode([]byte(jwksDataRSABytes))
	if block == nil || block.Type != "PUBLIC KEY" {
		childLogger.Error().Err(erro.ErrDecodeKey).Msg("erro Decode")
		return false, nil
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		childLogger.Error().Err(err).Msg("erro ParsePKIXPublicKey")
		return false, nil
	}
	publicKey = pubInterface.(*rsa.PublicKey)

	// Check with token is signed 
	claims := &core.JwtData{}
	tkn, err := jwt.ParseWithClaims(jwksData.Token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("error unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
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

func (a WorkerService) WellKnown(ctx context.Context) (*core.Jwks, error){
	childLogger.Debug().Msg("WellKnown")

	span := lib.Span(ctx, "service.WellKnown")
	defer span.End()

	nBase64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(a.RSA_Key.RSAPublicKeyByte))

	jKey := core.JKey{
		Type: "RSA",
		Algorithm: "RS256",
		JwtId: "1",
		NBase64: nBase64,
	}
	
	var arr_jKey []core.JKey
	arr_jKey = append(arr_jKey, jKey)

	jwks := core.Jwks{Keys: arr_jKey}
	
	return &jwks ,nil
}