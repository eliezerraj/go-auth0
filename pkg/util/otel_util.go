package util

import(
	"os"

	"github.com/rs/zerolog/log"	
	"github.com/joho/godotenv"
	"github.com/go-auth0/internal/model"
)

func GetOtelEnv() model.ConfigOTEL {
	log.Debug().Msg("GetOtelEnv")

	err := godotenv.Load(".env")
	if err != nil {
		log.Info().Err(err).Msg("No .env File !!!!")
	}

	var configOTEL	model.ConfigOTEL

	configOTEL.TimeInterval = 1
	configOTEL.TimeAliveIncrementer = 1
	configOTEL.TotalHeapSizeUpperBound = 100
	configOTEL.ThreadsActiveUpperBound = 10
	configOTEL.CpuUsageUpperBound = 100
	configOTEL.SampleAppPorts = []string{}

	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") !=  "" {	
		configOTEL.OtelExportEndpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}

	return configOTEL
}