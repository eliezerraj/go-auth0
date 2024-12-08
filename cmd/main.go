package main

import(
	"time"
	"context"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-auth0/pkg/util"
	"github.com/go-auth0/configs"
	"github.com/go-auth0/internal/usecase/jwt/adapter/controller"
	"github.com/go-auth0/internal/usecase/jwt"
	"github.com/go-auth0/internal/usecase/jwt/repository"
	"github.com/go-auth0/internal/model"
	"github.com/go-auth0/pkg/api/server"
	"github.com/go-auth0/pkg/aws_secret_manager"
	database "github.com/go-auth0/pkg/database/dynamo"
)

var(
	logLevel = zerolog.DebugLevel
	appServer	model.AppServer
)

func init(){
	log.Debug().Msg("init")
	zerolog.SetGlobalLevel(logLevel)

	infoPod, server := util.GetInfoPod()
	configOTEL := util.GetOtelEnv()
	dynamo := util.GetDynamoEnv()
	keys := util.LoadRSAKey()

	appServer.InfoPod = &infoPod
	appServer.Server = &server
	appServer.DynamoConfig = &dynamo
	appServer.ConfigOTEL = &configOTEL
	appServer.RSA_Key = keys
}

func main() {
	log.Debug().Msg("main")
	log.Debug().Interface("appServer :",appServer).Msg("")

	ctx, cancel := context.WithTimeout(	context.Background(), 
										time.Duration( appServer.Server.ReadTimeout ) * time.Second)
	defer cancel()

	configAWS, err := configs.GetAWSConfig(ctx, appServer.InfoPod.AWSRegion)
	if err != nil {
		panic("configuration error create new aws session " + err.Error())
	}

	database, err := database.NewDatabase(ctx, configAWS)
	if err != nil {
		log.Error().Err(err).Msg("erro NewDynamoRepository")
	}

	clientSecretManager, err := aws_secret_manager.NewClientSecretManager(configAWS)
	if err != nil {
		log.Error().Err(err).Msg("erro NewClientSecretManager")
	}

	repoWorker:= repository.NewRepoWorker(database, &appServer.DynamoConfig.UserTableName)

	usecase, err := jwt.NewWorkerService(ctx,
										clientSecretManager, 
										repoWorker,
										appServer.RSA_Key)
	if err != nil {
		log.Error().Err(err).Msg("erro NewWorkerService")
		panic(err)
	}

	httpWorkerAdapter 	:= controller.NewHttpWorkerAdapter(usecase)
	httpServer 			:= server.NewHttpAppServer(appServer.Server)

	httpServer.StartHttpAppServer(ctx, &httpWorkerAdapter, &appServer)
}