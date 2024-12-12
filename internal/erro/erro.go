package erro

import (
	"errors"
)

var (
	ErrStatusUnauthorized 	= errors.New("invalid Token")
	ErrTokenExpired		 	= errors.New("token expired")
	ErrBadRequest		 	= errors.New("internal error")
	ErrUnmarshal			= errors.New("erro Unmarshall")
	ErrMethodNotAllowed		= errors.New("method not allowed")
	ErrOpenDatabase 		= errors.New("open Database error")
	ErrQuery 				= errors.New("query error")
	ErrPreparedQuery 		= errors.New("prepare dynamo query erro")
	ErrNotFound 			= errors.New("data not found")
	ErrInsert 				= errors.New("insert Error")
	ErrList					= errors.New("list Error")
	ErrQueryEmpty			= errors.New("query parameters missing")
	ErrTokenStillValid		= errors.New("token is still valid")
	ErrDecodeKey			= errors.New("error decode rsa key")
	ErrCertRevoked			= errors.New("error cert revoke")
	ErrParseCert			= errors.New("error parse cert")
	ErrDecodeCert			= errors.New("error decode cert")
)