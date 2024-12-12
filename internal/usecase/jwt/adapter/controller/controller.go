package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/go-auth0/internal/model"
	"github.com/go-auth0/internal/erro"
	"github.com/go-auth0/pkg/observability"
	"github.com/go-auth0/internal/usecase/jwt"

	"github.com/gorilla/mux"
)

var childLogger = log.With().Str("adapter", "controller").Logger()

type HttpWorkerAdapter struct {
	usecase 	*jwt.WorkerService
}

func NewHttpWorkerAdapter(usecase *jwt.WorkerService) HttpWorkerAdapter {
	childLogger.Debug().Msg("NewHttpWorkerAdapter")

	return HttpWorkerAdapter{
		usecase: usecase,
	}
}

type APIError struct {
	StatusCode	int  `json:"statusCode"`
	Msg			string `json:"msg"`
}

func (e APIError) Error() string {
	return e.Msg
}

func NewAPIError(statusCode int, err error) APIError {
	return APIError{
		StatusCode: statusCode,
		Msg:		err.Error(),
	}
}

func WriteJSON(rw http.ResponseWriter, code int, v any) error{
	rw.WriteHeader(code)
	return json.NewEncoder(rw).Encode(v)
}

func (h *HttpWorkerAdapter) Health(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("Health")

	health := true
	json.NewEncoder(rw).Encode(health)
}

func (h *HttpWorkerAdapter) Live(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("Live")

	live := true
	json.NewEncoder(rw).Encode(live)
}

func (h *HttpWorkerAdapter) OAUTHCredential(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("OAUTHCredential")

	span := observability.Span(req.Context(), "controller.OAUTHCredential")
	defer span.End()

	credential := model.Credential{}
	err := json.NewDecoder(req.Body).Decode(&credential)
    if err != nil {
		apiError := NewAPIError(http.StatusBadRequest, erro.ErrUnmarshal)
		return apiError
    }
	defer req.Body.Close()

	res, err := h.usecase.OAUTHCredential(req.Context(), credential)
	if err != nil {
		var apiError APIError
		switch err {
			case erro.ErrStatusUnauthorized:
				apiError = NewAPIError(http.StatusForbidden, err)
			case erro.ErrTokenExpired:
				apiError = NewAPIError(http.StatusForbidden, err)
			default:
				apiError = NewAPIError(http.StatusInternalServerError, err)
			}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}

func (h *HttpWorkerAdapter) Validation(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("Validation")

	span := observability.Span(req.Context(), "controller.Validation")
	defer span.End()

	var token model.Credential
	var tokenHeader string
	var bearerToken string

	if reqHeadersBytes, err := json.Marshal(req.Header); err != nil {
		apiError := NewAPIError(http.StatusBadRequest, erro.ErrUnmarshal)
		return apiError
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
		apiError := NewAPIError(http.StatusUnauthorized, erro.ErrUnmarshal)
		return apiError
	}
	
	tokenSlice := strings.Split(tokenHeader, " ")
	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	} else {
		bearerToken = tokenHeader
	}

	token.Token = bearerToken

	res, err := h.usecase.TokenValidation(req.Context(), token)
	if err != nil {
		var apiError APIError
		switch err {
		case erro.ErrStatusUnauthorized:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		case erro.ErrTokenExpired:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		default:
			apiError = NewAPIError(http.StatusInternalServerError, err)
		}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}

func (h *HttpWorkerAdapter) TokenValidation(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("TokenValidation")

	span := observability.Span(req.Context(), "controller.TokenValidation")
	defer span.End()

	var token model.Credential

	vars := mux.Vars(req)
	varToken := vars["id"]

	token.Token = varToken
	
	res, err := h.usecase.TokenValidation(req.Context(), token)
	if err != nil {
		var apiError APIError
		switch err {
			case erro.ErrStatusUnauthorized:
				apiError = NewAPIError(http.StatusForbidden, err)
			case erro.ErrTokenExpired:
				apiError = NewAPIError(http.StatusForbidden, err)
			default:
				apiError = NewAPIError(http.StatusInternalServerError, err)
			}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}

func (h *HttpWorkerAdapter) RefreshToken(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("RefreshToken")

	span := observability.Span(req.Context(), "controller.RefreshToken")
	defer span.End()

	token := model.Credential{}
	err := json.NewDecoder(req.Body).Decode(&token)
    if err != nil {
		apiError := NewAPIError(http.StatusBadRequest, erro.ErrUnmarshal)
		return apiError
    }
	defer req.Body.Close()

	res, err := h.usecase.RefreshToken(req.Context(), token)
	if err != nil {
		var apiError APIError
		switch err {
		case erro.ErrTokenExpired:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		case erro.ErrStatusUnauthorized:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		default:
			apiError = NewAPIError(http.StatusInternalServerError, err)
		}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}

func (h *HttpWorkerAdapter) OAUTHCredentialRSA(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("OAUTHCredentialRSA")

	span := observability.Span(req.Context(), "controller.OAUTHCredentialRSA")
	defer span.End()

	credential := model.Credential{}
	err := json.NewDecoder(req.Body).Decode(&credential)
    if err != nil {
		apiError := NewAPIError(http.StatusBadRequest, erro.ErrUnmarshal)
		return apiError
    }
	defer req.Body.Close()

	res, err := h.usecase.OAUTHCredentialRSA(req.Context(), credential)
	if err != nil {
		var apiError APIError
		switch err {
			case erro.ErrStatusUnauthorized:
				apiError = NewAPIError(http.StatusForbidden, err)
			case erro.ErrTokenExpired:
				apiError = NewAPIError(http.StatusForbidden, err)
			default:
				apiError = NewAPIError(http.StatusInternalServerError, err)
			}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}

func (h *HttpWorkerAdapter) WellKnown(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("WellKnown")

	span := observability.Span(req.Context(), "controller.WellKnown")
	defer span.End()

	var jwks model.Credential
	vars := mux.Vars(req)
	varJwks := vars["jkws"]
	jwks.Token = varJwks
	
	res, err := h.usecase.WellKnown(req.Context())
	if err != nil {
		var apiError APIError
		switch err {
			case erro.ErrStatusUnauthorized:
				apiError = NewAPIError(http.StatusForbidden, err)
			case erro.ErrTokenExpired:
				apiError = NewAPIError(http.StatusForbidden, err)
			default:
				apiError = NewAPIError(http.StatusInternalServerError, err)
			}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}

func (h *HttpWorkerAdapter) ValidationRSA(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("ValidationRSA")

	span := observability.Span(req.Context(), "controller.ValidationRSA")
	defer span.End()

	var token model.Credential
	var tokenHeader string
	var bearerToken string

	if reqHeadersBytes, err := json.Marshal(req.Header); err != nil {
		apiError := NewAPIError(http.StatusBadRequest, erro.ErrUnmarshal)
		return apiError
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
		apiError := NewAPIError(http.StatusUnauthorized, erro.ErrUnmarshal)
		return apiError
	}
	
	tokenSlice := strings.Split(tokenHeader, " ")
	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	} else {
		bearerToken = tokenHeader
	}

	token.Token = bearerToken

	res, err := h.usecase.TokenValidationRSA(req.Context(), token)
	if err != nil {
		var apiError APIError
		switch err {
		case erro.ErrStatusUnauthorized:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		case erro.ErrTokenExpired:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		default:
			apiError = NewAPIError(http.StatusInternalServerError, err)
		}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}

func (h *HttpWorkerAdapter) TokenValidationRSA(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("TokenValidationRSA")

	span := observability.Span(req.Context(), "controller.TokenValidationRSA")
	defer span.End()

	var token model.Credential

	vars := mux.Vars(req)
	varToken := vars["id"]

	token.Token = varToken

	res, err := h.usecase.TokenValidationRSA(req.Context(), token)
	if err != nil {
		var apiError APIError
		switch err {
		case erro.ErrStatusUnauthorized:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		case erro.ErrTokenExpired:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		default:
			apiError = NewAPIError(http.StatusInternalServerError, err)
		}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}

func (h *HttpWorkerAdapter) ValidationTokenAndPubKey(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("ValidationTokenAndPubKey")

	span := observability.Span(req.Context(), "controller.ValidationTokenAndPubKey")
	defer span.End()

	jwksData := model.JwksData{}
	err := json.NewDecoder(req.Body).Decode(&jwksData)
    if err != nil {
		apiError := NewAPIError(http.StatusBadRequest, erro.ErrUnmarshal)
		return apiError
    }
	defer req.Body.Close()

	res, err := h.usecase.ValidationTokenAndPubKey(req.Context(), jwksData)
	if err != nil {
		var apiError APIError
		switch err {
		case erro.ErrStatusUnauthorized:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		case erro.ErrTokenExpired:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		default:
			apiError = NewAPIError(http.StatusInternalServerError, err)
		}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}

func (h *HttpWorkerAdapter) RefreshTokenRSA(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("RefreshTokenRSA")

	span := observability.Span(req.Context(), "controller.RefreshTokenRSA")
	defer span.End()

	token := model.Credential{}
	err := json.NewDecoder(req.Body).Decode(&token)
    if err != nil {
		apiError := NewAPIError(http.StatusBadRequest, erro.ErrUnmarshal)
		return apiError
    }
	defer req.Body.Close()

	res, err := h.usecase.RefreshTokenRSA(req.Context(), token)
	if err != nil {
		var apiError APIError
		switch err {
		case erro.ErrTokenExpired:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		case erro.ErrStatusUnauthorized:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		default:
			apiError = NewAPIError(http.StatusInternalServerError, err)
		}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}

func (h *HttpWorkerAdapter) ValidCRLToken(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("ValidCRLToken")

	span := observability.Span(req.Context(), "controller.ValidCRLToken")
	defer span.End()

	cert := model.Credential{}
	err := json.NewDecoder(req.Body).Decode(&cert)
    if err != nil {
		apiError := NewAPIError(http.StatusBadRequest, erro.ErrUnmarshal)
		return apiError
    }
	defer req.Body.Close()

	res, err := h.usecase.ValidCRLToken(req.Context(), cert)
	if err != nil {
		var apiError APIError
		switch err {
		case erro.ErrParseCert:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		case erro.ErrParseCert:
			apiError = NewAPIError(http.StatusUnauthorized, err)
		default:
			apiError = NewAPIError(http.StatusInternalServerError, err)
		}
		return apiError
	}

	return WriteJSON(rw, http.StatusOK, res)
}
