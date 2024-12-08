package jwt

import (
	"context"
	"fmt"
	"encoding/json"
	"time"
	"encoding/base64"
    "encoding/pem"
	"crypto/rsa"
	"crypto/x509"

	"github.com/rs/zerolog/log"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"github.com/go-auth0/pkg/observability"
	"github.com/go-auth0/internal/erro"
	"github.com/go-auth0/internal/model"
	"github.com/go-auth0/pkg/aws_secret_manager"
	"github.com/go-auth0/internal/usecase/jwt/repository"
)

var childLogger = log.With().Str("usecase", "jwt").Logger()

type WorkerService struct {
	awsClientSecretManager 	*aws_secret_manager.AwsClientSecretManager
	workerDynamo			*repository.RepoWorker
	rsaKey 					*model.RSA_Key
}

func NewWorkerService(	ctx context.Context,
						awsClientSecretManager *aws_secret_manager.AwsClientSecretManager, 
						workerDynamo	*repository.RepoWorker,
						rsaKey *model.RSA_Key ) (*WorkerService, error){
	childLogger.Debug().Msg("NewWorkerService")

	res_secret, err := awsClientSecretManager.GetSecret(ctx, rsaKey.SecretNameH256)
	if err != nil {
		return nil, err
	}
	var secretData map[string]string
	if err := json.Unmarshal([]byte(*res_secret), &secretData); err != nil {
		return nil, fmt.Errorf("failed to parse secret JSON: %w", err)
	}

	rsaKey.JwtKey = secretData["secret-value-h256"]

	_key_rsa_priv, err := ParsePemToRSAPriv(&rsaKey.Key_rsa_priv_pem)
	if err != nil{
		childLogger.Error().Err(err).Msg("erro ParsePemToRSA !!!!")
	}
	_key_rsa_pub, err := ParsePemToRSAPub(&rsaKey.Key_rsa_pub_pem)
	if err != nil{
		childLogger.Error().Err(err).Msg("erro ParsePemToRSA !!!!")
	}

	rsaKey.Key_rsa_priv = _key_rsa_priv
	rsaKey.Key_rsa_pub = _key_rsa_pub

	return &WorkerService{
		awsClientSecretManager: awsClientSecretManager,
		workerDynamo: 	workerDynamo,
		rsaKey:	rsaKey,
	}, nil
}

func ParsePemToRSAPriv(private_key *string) (*rsa.PrivateKey, error){
	childLogger.Debug().Msg("ParsePemToRSA")

	block, _ := pem.Decode([]byte(*private_key))
	if block == nil || block.Type != "PRIVATE KEY" {
		childLogger.Error().Err(erro.ErrDecodeKey).Msg("erro Decode")
		return nil, erro.ErrDecodeKey
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		childLogger.Error().Err(err).Msg("erro ParsePKCS8PrivateKey")
		return nil, err
	}

	key_rsa := privateKey.(*rsa.PrivateKey)

	return key_rsa, nil
}

func ParsePemToRSAPub(public_key *string) (*rsa.PublicKey, error){
	childLogger.Debug().Msg("ParsePemToRSA")

	block, _ := pem.Decode([]byte(*public_key))
	if block == nil || block.Type != "PUBLIC KEY" {
		childLogger.Error().Err(erro.ErrDecodeKey).Msg("erro Decode")
		return nil, erro.ErrDecodeKey
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		childLogger.Error().Err(err).Msg("erro ParsePKCS8PrivateKey")
		return nil, err
	}

	key_rsa := pubInterface.(*rsa.PublicKey)

	return key_rsa, nil
}

func (w *WorkerService) OAUTHCredential(ctx context.Context, credential model.Credential) (*model.Authentication, error){
	childLogger.Debug().Msg("OAUTHCredential")

	span := observability.Span(ctx, "usecase.OAUTHCredential")
	defer span.End()

	_, err := w.workerDynamo.Login(ctx, credential)
	if err != nil {
		return nil, err
	}

	// get scopes associated with a credential
	credential_scope, err := w.workerDynamo.QueryCredentialScope(ctx, credential)
	if err != nil {
		return nil, err
	}

	// Set a JWT expiration date 
	expirationTime := time.Now().Add(720 * time.Minute)

	newUUID := uuid.New()
	uuidString := newUUID.String()

	// Create a JWT Oauth 2.0 with all scopes and expiration date
	jwtData := &model.JwtData{
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
	tokenString, err := token.SignedString([]byte(w.rsaKey.JwtKey))
	if err != nil {
		return nil, err
	}
	
	auth := model.Authentication{Token: tokenString, 
								ExpirationTime :expirationTime}	

	return &auth ,nil
}

func (w *WorkerService) TokenValidation(ctx context.Context, credential model.Credential) (bool, error){
	childLogger.Debug().Msg("TokenValidation")
	childLogger.Debug().Interface("=> credential : ", credential.Token).Msg("")
	childLogger.Debug().Msg("--------------------------------------")

	span := observability.Span(ctx, "usecase.TokenValidation")
	defer span.End()

	// Check with token is signed 
	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(credential.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(w.rsaKey.JwtKey), nil
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

func (w *WorkerService) RefreshToken(ctx context.Context, credential model.Credential) (*model.Authentication, error){
	childLogger.Debug().Msg("RefreshToken")
	childLogger.Debug().Msg("--------------------------------------")

	span := observability.Span(ctx, "usecase.RefreshToken")
	defer span.End()

	// Check with token is signed 
	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(credential.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(w.rsaKey.JwtKey), nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	// Check if the token is still valid
	/*if time.Until(claims.ExpiresAt.Time) > (50 * time.Minute) {
		return nil, erro.ErrTokenStillValid
	}*/

	// Set a new tokens claims
	expirationTime := time.Now().Add(60 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	claims.ISS = "lambda-go-autentication-refreshed"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(w.rsaKey.JwtKey))
	if err != nil {
		childLogger.Error().Err(err).Msg("error SignedString")
		return nil, erro.ErrStatusUnauthorized
	}

	auth := model.Authentication{	Token: tokenString, 
									ExpirationTime :expirationTime}

	return &auth,nil
}

func (w *WorkerService) OAUTHCredentialRSA(ctx context.Context, credential model.Credential) (*model.Authentication, error){
	childLogger.Debug().Msg("OAUTHCredentialRSA")

	span := observability.Span(ctx, "usecase.OAUTHCredentialRSA")
	defer span.End()

	_, err := w.workerDynamo.Login(ctx, credential)
	if err != nil {
		return nil, err
	}

	// get scopes associated with a credential
	credential_scope, err := w.workerDynamo.QueryCredentialScope(ctx, credential)
	if err != nil {
		return nil, err
	}

	// Set a JWT expiration date 
	expirationTime := time.Now().Add(720 * time.Minute)

	newUUID := uuid.New()
	uuidString := newUUID.String()

	// Create a JWT Oauth 2.0 with all scopes and expiration date
	jwtData := &model.JwtData{
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
	tokenString, err := token.SignedString(w.rsaKey.Key_rsa_priv)
	if err != nil {
		return nil, err
	}
	
	auth := model.Authentication{Token: tokenString, 
								ExpirationTime :expirationTime}	

	return &auth ,nil
}

func(w *WorkerService) WellKnown(ctx context.Context) (*model.Jwks, error){
	childLogger.Debug().Msg("WellKnown")

	span := observability.Span(ctx, "usecase.WellKnown")
	defer span.End()

	nBase64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(w.rsaKey.Key_rsa_pub_pem))

	jKey := model.JKey{
		Type: "RSA",
		Algorithm: "RS256",
		JwtId: "1",
		NBase64: nBase64,
	}
	
	var arr_jKey []model.JKey
	arr_jKey = append(arr_jKey, jKey)

	jwks := model.Jwks{Keys: arr_jKey}
	
	return &jwks ,nil
}

func(w *WorkerService) TokenValidationRSA(ctx context.Context, credential model.Credential) (bool, error){
	childLogger.Debug().Msg("TokenValidationRSA")
	childLogger.Debug().Interface("=> credential : ", credential).Msg("")
	childLogger.Debug().Msg("--------------------------------------")

	span := observability.Span(ctx, "usecase.TokenValidationRSA")
	defer span.End()

	// Check with token is signed 
	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(credential.Token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("error unexpected signing method: %v", token.Header["alg"])
		}
		return w.rsaKey.Key_rsa_pub, nil
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

func(w *WorkerService) ValidationTokenAndPubKey(ctx context.Context, jwksData model.JwksData) (bool, error){
	childLogger.Debug().Msg("ValidationTokenAndPubKey")
	childLogger.Debug().Interface("=> jwksData : ", jwksData).Msg("")
	childLogger.Debug().Msg("--------------------------------------")

	span := observability.Span(ctx, "usecase.ValidationTokenAndPubKey")
	defer span.End()

	rsa_pub_key_pem, err := base64.RawStdEncoding.DecodeString(jwksData.RSAPublicKeyB64)
	if err != nil {
		childLogger.Error().Err(err).Msg("erro RawURLEncoding.DecodeString")
		return false, nil
	}

	rsa_pub_key_pem_str := string(rsa_pub_key_pem)
	_key_rsa_pub, err := ParsePemToRSAPub(&rsa_pub_key_pem_str)
	if err != nil{
		childLogger.Error().Err(err).Msg("erro ParsePemToRSA !!!!")
	}

	// Check with token is signed 
	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(jwksData.Token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("error unexpected signing method: %v", token.Header["alg"])
		}
		return _key_rsa_pub, nil
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

func (w *WorkerService) RefreshTokenRSA(ctx context.Context, credential model.Credential) (*model.Authentication, error){
	childLogger.Debug().Msg("RefreshTokenRSA")
	childLogger.Debug().Interface("=> credential : ", credential).Msg("")
	childLogger.Debug().Msg("--------------------------------------")

	span := observability.Span(ctx, "usecase.RefreshTokenRSA")
	defer span.End()

	// Check with token is signed 
	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(credential.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return w.rsaKey.Key_rsa_pub, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	// Check if the token is still valid
	/*if time.Until(claims.ExpiresAt.Time) > (50 * time.Minute) {
		return nil, erro.ErrTokenStillValid
	}*/

	// Set a new tokens claims
	expirationTime := time.Now().Add(60 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	claims.ISS = "lambda-go-autentication-refreshed"

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(w.rsaKey.Key_rsa_priv)
	
	if err != nil {
		childLogger.Error().Err(err).Msg("error SignedString")
		return nil, erro.ErrStatusUnauthorized
	}

	childLogger.Debug().Interface("=> tokenString : ", tokenString).Msg("")

	auth := model.Authentication{	Token: tokenString, 
									ExpirationTime :expirationTime}

	return &auth,nil
}