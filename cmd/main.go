package main

import(
	"time"
	"context"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-auth0/internal/util"
	"github.com/go-auth0/internal/handler"
	"github.com/go-auth0/internal/core"
	"github.com/go-auth0/internal/service"
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

	appServer.InfoPod = &infoPod
	appServer.Server = &server
	appServer.ConfigOTEL = &configOTEL
}

func main() {
	log.Debug().Msg("main")
	log.Debug().Interface("appServer :",appServer).Msg("")

	ctx, cancel := context.WithTimeout(	context.Background(), 
										time.Duration( appServer.Server.ReadTimeout ) * time.Second)
	defer cancel()

	var jwtKey = "my-secret-key"

	log.Debug().Str("======== > jwtKey", jwtKey).Msg("")
	
	workerService := service.NewWorkerService([]byte(jwtKey))
	
	httpWorkerAdapter 	:= handler.NewHttpWorkerAdapter(workerService)
	httpServer 			:= handler.NewHttpAppServer(appServer.Server)

	httpServer.StartHttpAppServer(ctx, &httpWorkerAdapter, &appServer)
}