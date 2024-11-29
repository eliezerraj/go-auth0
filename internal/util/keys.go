package util

	import(
		"os"
		"crypto/x509"
		"encoding/pem"
		"crypto/rsa"
		"github.com/joho/godotenv"

		"github.com/go-auth0/internal/erro"
		"github.com/go-auth0/internal/core"
	)

func LoadRSAKey() (*core.RSA_Key){
	childLogger.Debug().Msg("LoadRSAKey")

	var keys core.RSA_Key

	err := godotenv.Load(".env")
	if err != nil {
		childLogger.Info().Err(err).Msg("env file not found !!!")
	}
	if os.Getenv("SECRET_NAME_H256") !=  "" {
		keys.SecretNameH256 = os.Getenv("SECRET_NAME_H256")
	}

	// Load Private key
	private_key, err := os.ReadFile("./cmd/vault/private_key.pem")
	if err != nil {
		childLogger.Error().Err(err).Msg("erro ReadFile - private_key")
		return nil
	}

	public_key, err := os.ReadFile("./cmd/vault/public_key.pem")
	if err != nil {
		childLogger.Error().Err(err).Msg("erro ReadFile - public_key")
		return nil
	}

	keys.RSAPrivateKeyByte = private_key
	keys.RSAPublicKeyByte = public_key

	block, _ := pem.Decode(private_key)
	if block == nil || block.Type != "PRIVATE KEY" {
		childLogger.Error().Err(erro.ErrDecodeKey).Msg("erro Decode")
		return nil
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		childLogger.Error().Err(err).Msg("erro ParsePKCS8PrivateKey")
		return nil
	}

	keys.PrivateKeyPem = privateKey.(*rsa.PrivateKey)

	return &keys
}