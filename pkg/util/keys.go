package util

	import(
		"os"
		"github.com/joho/godotenv"

		"github.com/rs/zerolog/log"
		"github.com/go-auth0/internal/model"
	)

func LoadRSAKey() (*model.RSA_Key){
	log.Debug().Msg("LoadRSAKey")

	var keys model.RSA_Key

	err := godotenv.Load(".env")
	if err != nil {
		log.Info().Err(err).Msg("env file not found !!!")
	}

	if os.Getenv("SECRET_NAME_H256") !=  "" {
		keys.SecretNameH256 = os.Getenv("SECRET_NAME_H256")
	}

	// Load Private key
	private_key, err := os.ReadFile("../cmd/vault/private_key.pem")
	if err != nil {
		log.Error().Err(err).Msg("erro ReadFile - private_key")
		return nil
	}

	public_key, err := os.ReadFile("../cmd/vault/public_key.pem")
	if err != nil {
		log.Error().Err(err).Msg("erro ReadFile - public_key")
		return nil
	}

	keys.Key_rsa_priv_pem = string(private_key)
	keys.Key_rsa_pub_pem = string(public_key)

	return &keys
}