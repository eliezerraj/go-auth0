package util

import(
	"os"
	
	"github.com/rs/zerolog/log"	
	"github.com/joho/godotenv"
	"github.com/go-auth0/internal/model"
)

func GetDynamoEnv() model.DatabaseDynamo {
	log.Debug().Msg("GetDynamoEnv")

	err := godotenv.Load(".env")
	if err != nil {
		log.Info().Err(err).Msg("env file not found !!!")
	}
	
	var databaseDynamo	model.DatabaseDynamo

	if os.Getenv("USER_TABLE_NAME") !=  "" {
		databaseDynamo.UserTableName = os.Getenv("USER_TABLE_NAME")
	}
	if os.Getenv("AWS_REGION") !=  "" {
		databaseDynamo.AwsRegion = os.Getenv("AWS_REGION")
	}

	return databaseDynamo
}