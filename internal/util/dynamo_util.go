package util

import(
	"os"

	"github.com/joho/godotenv"
	"github.com/go-auth0/internal/core"
)

func GetDynamoEnv() core.DatabaseDynamo {
	childLogger.Debug().Msg("GetDynamoEnv")

	err := godotenv.Load(".env")
	if err != nil {
		childLogger.Info().Err(err).Msg("env file not found !!!")
	}
	
	var databaseDynamo	core.DatabaseDynamo

	if os.Getenv("USER_TABLE_NAME") !=  "" {
		databaseDynamo.UserTableName = os.Getenv("USER_TABLE_NAME")
	}
	if os.Getenv("AWS_REGION") !=  "" {
		databaseDynamo.AwsRegion = os.Getenv("AWS_REGION")
	}

	return databaseDynamo
}