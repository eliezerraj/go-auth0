package handler

import (	
	"net/http"
	"encoding/json"

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
		case erro.ErrNotFound:
			rw.WriteHeader(404)
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