package handler

import (
	"time"
	"encoding/json"
	"net/http"
	"strconv"
	"os"
	"os/signal"
	"syscall"
	"context"

	"github.com/rs/zerolog/log"
	"github.com/gorilla/mux"

	"github.com/go-auth0/internal/lib"
	"github.com/go-auth0/internal/core"
	"github.com/go-auth0/internal/handler/controller"
	"github.com/go-auth0/internal/handler/middleware"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/contrib/propagators/aws/xray"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
)

var childLogger = log.With().Str("handler", "server").Logger()

type HttpServer struct {
	httpServer	*core.Server
}

func NewHttpAppServer(httpServer *core.Server) HttpServer {
	childLogger.Debug().Msg("NewHttpAppServer")

	return HttpServer{httpServer: httpServer }
}

func (h HttpServer) StartHttpAppServer(	ctx context.Context, 
										httpWorkerAdapter *controller.HttpWorkerAdapter,
										appServer *core.AppServer) {
	childLogger.Info().Msg("StartHttpAppServer")
	// ---------------------- OTEL ---------------
	childLogger.Info().Str("OTEL_EXPORTER_OTLP_ENDPOINT :", appServer.ConfigOTEL.OtelExportEndpoint).Msg("")
	
	tp := lib.NewTracerProvider(ctx, appServer.ConfigOTEL, appServer.InfoPod)
	defer func() { 
		err := tp.Shutdown(ctx)
		if err != nil{
			childLogger.Error().Err(err).Msg("Erro closing OTEL tracer !!!")
		}
	}()
	otel.SetTextMapPropagator(xray.Propagator{})
	otel.SetTracerProvider(tp)

	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.Use(middleware.MiddleWareHandlerHeader)

	myRouter.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		childLogger.Debug().Msg("/")
		json.NewEncoder(rw).Encode(appServer)
	})

	myRouter.HandleFunc("/info", func(rw http.ResponseWriter, req *http.Request) {
		childLogger.Debug().Msg("/info")
		childLogger.Debug().Interface("===> : ", req.TLS).Msg("")
		json.NewEncoder(rw).Encode(&appServer)
	})

	health := myRouter.Methods(http.MethodGet, http.MethodOptions).Subrouter()
    health.HandleFunc("/health", httpWorkerAdapter.Health)

	live := myRouter.Methods(http.MethodGet, http.MethodOptions).Subrouter()
    live.HandleFunc("/live", httpWorkerAdapter.Live)

	validToken := myRouter.Methods(http.MethodGet, http.MethodOptions).Subrouter()
	validToken.Handle("/tokenValidation/{id}",middleware.MiddleWareErrorHandler(httpWorkerAdapter.TokenValidation),)
	validToken.Use(otelmux.Middleware("go-auth0"))

	validateToken := myRouter.Methods(http.MethodPost, http.MethodOptions).Subrouter()
	validateToken.Handle("/validate",middleware.MiddleWareErrorHandler(httpWorkerAdapter.Validation),)
	validateToken.Use(otelmux.Middleware("go-auth0"))

	oauthCredential := myRouter.Methods(http.MethodPost, http.MethodOptions).Subrouter()
	oauthCredential.Handle("/oauth_credential",middleware.MiddleWareErrorHandler(httpWorkerAdapter.OAUTHCredential),)
	oauthCredential.Use(otelmux.Middleware("go-auth0"))

	oauthCredentialRSA := myRouter.Methods(http.MethodPost, http.MethodOptions).Subrouter()
	oauthCredentialRSA.Handle("/oauth_credential_rsa",middleware.MiddleWareErrorHandler(httpWorkerAdapter.OAUTHCredentialRSA),)
	oauthCredentialRSA.Use(otelmux.Middleware("go-auth0"))

	validateTokenRSA := myRouter.Methods(http.MethodPost, http.MethodOptions).Subrouter()
	validateTokenRSA.Handle("/validate_rsa",middleware.MiddleWareErrorHandler(httpWorkerAdapter.TokenValidationRSA),)
	validateTokenRSA.Use(otelmux.Middleware("go-auth0"))

	wellKnown := myRouter.Methods(http.MethodGet, http.MethodOptions).Subrouter()
	wellKnown.Handle("/wellKnown/{id}",middleware.MiddleWareErrorHandler(httpWorkerAdapter.WellKnown),)
	wellKnown.Use(otelmux.Middleware("go-auth0"))

	// ---------------
	srv := http.Server{
		Addr:         ":" +  strconv.Itoa(h.httpServer.Port),      	
		Handler:      myRouter,                	          
		ReadTimeout:  time.Duration(h.httpServer.ReadTimeout) * time.Second,   
		WriteTimeout: time.Duration(h.httpServer.WriteTimeout) * time.Second,  
		IdleTimeout:  time.Duration(h.httpServer.IdleTimeout) * time.Second,
	}

	childLogger.Info().Str("Service Port : ", strconv.Itoa(h.httpServer.Port)).Msg("Service Port")

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			childLogger.Error().Err(err).Msg("Cancel http mux server !!!")
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch

	if err := srv.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
		childLogger.Error().Err(err).Msg("WARNING Dirty Shutdown !!!")
		return
	}
	childLogger.Info().Msg("Stop Done !!!!")
}