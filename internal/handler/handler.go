package handler

import (	
	"fmt"
	"net/http"
	"encoding/json"
	"strings"

	"github.com/go-auth0/internal/core"
	"github.com/go-auth0/internal/erro"
	"github.com/go-auth0/internal/lib"
	
	"github.com/gorilla/mux"
)

func MiddleWareHandlerHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		childLogger.Debug().Msg("-------------- MiddleWareHandlerHeader (INICIO)  --------------")
		
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers","Content-Type,access-control-allow-origin, access-control-allow-headers")

		childLogger.Debug().Msg("-------------- MiddleWareHandlerHeader (FIM) ----------------")
		next.ServeHTTP(w, r)
	})
}

func (h *HttpWorkerAdapter) Health(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("Health")

	health := true
	json.NewEncoder(rw).Encode(health)
	return
}

func (h *HttpWorkerAdapter) Live(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("Live")

	live := true
	json.NewEncoder(rw).Encode(live)
	return
}

func (h *HttpWorkerAdapter) TokenValidation(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("TokenValidation")

	span := lib.Span(req.Context(), "handler.TokenValidation")
	defer span.End()

	var token core.Credential

	vars := mux.Vars(req)
	varToken := vars["id"]

	token.Token = varToken
	
	res, err := h.workerService.TokenValidation(req.Context(), token)
	if err != nil {
		switch err {
		case erro.ErrStatusUnauthorized:
			rw.WriteHeader(403)
			json.NewEncoder(rw).Encode(err.Error())
			return
		case erro.ErrTokenExpired:
			rw.WriteHeader(403)
			json.NewEncoder(rw).Encode(err.Error())
			return
		default:
			rw.WriteHeader(500)
			json.NewEncoder(rw).Encode(err.Error())
			return
		}
	}

	json.NewEncoder(rw).Encode(res)
	return
}

func (h *HttpWorkerAdapter) Validation(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("Validation")

	span := lib.Span(req.Context(), "handler.Validation")
	defer span.End()

	var token core.Credential
	var tokenHeader string
	var bearerToken string

	if reqHeadersBytes, err := json.Marshal(req.Header); err != nil {
		childLogger.Error().Err(err).Msg("Could not Marshal http headers !!!")
		rw.WriteHeader(401)
		json.NewEncoder(rw).Encode(erro.ErrUnmarshal.Error())
		return
	} else {
		fmt.Println("----------------------------------------------------------")
		childLogger.Debug().Str("=> 1 . req.Headers : ", string(reqHeadersBytes)).Msg("")
	}
	fmt.Println("----------------------------------------------------------")
	childLogger.Debug().Interface("==> 2 . req.Context() : ", req.Context()).Msg("")
	fmt.Println("----------------------------------------------------------")
	childLogger.Debug().Str("===> 3 . Header.Authorization : ", string(req.Header.Get("Authorization")) ).Msg("")
	fmt.Println("----------------------------------------------------------")

	// Extract the token from header
	if (req.Header.Get("Authorization") != "")  {
		tokenHeader = req.Header.Get("Authorization")
	} else if (req.Header.Get("authorization") != "") {
		tokenHeader = req.Header.Get("authorization")
	} else {
		rw.WriteHeader(401)
		json.NewEncoder(rw).Encode(erro.ErrStatusUnauthorized.Error())
		return
	}
	
	tokenSlice := strings.Split(tokenHeader, " ")
	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	} else {
		bearerToken = tokenHeader
	}

	token.Token = bearerToken

	res, err := h.workerService.TokenValidation(req.Context(), token)
	if err != nil {
		switch err {
		case erro.ErrStatusUnauthorized:
			rw.WriteHeader(401)
			json.NewEncoder(rw).Encode(err.Error())
			return
		case erro.ErrTokenExpired:
			rw.WriteHeader(401)
			json.NewEncoder(rw).Encode(err.Error())
			return
		default:
			rw.WriteHeader(500)
			json.NewEncoder(rw).Encode(err.Error())
			return
		}
	}

	json.NewEncoder(rw).Encode(res)
	return
}