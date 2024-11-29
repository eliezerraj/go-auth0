package main

import(
	"time"
	"context"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-auth0/internal/util"
	"github.com/go-auth0/internal/handler"
	"github.com/go-auth0/internal/handler/controller"
	"github.com/go-auth0/internal/core"
	"github.com/go-auth0/internal/service"
	"github.com/go-auth0/internal/config/parameter_store_aws"
	"github.com/go-auth0/internal/config/secret_manager_aws"
	"github.com/go-auth0/internal/repository/dynamo"
)

var(
	logLevel 	= 	zerolog.DebugLevel
	appServer	core.AppServer
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

	dynamoRepository, err := dynamo.NewDynamoRepository(ctx, *appServer.DynamoConfig)
	if err != nil {
		log.Error().Err(err).Msg("erro NewDynamoRepository")
	}

	clientSsm, err := parameter_store_aws.NewClientParameterStore(ctx, *appServer.DynamoConfig)
	if err != nil {
		log.Error().Err(err).Msg("erro NewClientParameterStore")
	}
	
	clientSecretManager, err := secret_manager_aws.NewClientSecretManager(ctx, *appServer.DynamoConfig)
	if err != nil {
		log.Error().Err(err).Msg("erro NewClientSecretManager")
	}

	workerService, err := service.NewWorkerService(	ctx,
												clientSecretManager, 
												clientSsm, 
												dynamoRepository,
												appServer.RSA_Key,
											)
	if err != nil {
		log.Error().Err(err).Msg("erro NewWorkerService")
		panic(err)
	}

	httpWorkerAdapter 	:= controller.NewHttpWorkerAdapter(workerService)
	httpServer 			:= handler.NewHttpAppServer(appServer.Server)

	httpServer.StartHttpAppServer(ctx, &httpWorkerAdapter, &appServer)
}