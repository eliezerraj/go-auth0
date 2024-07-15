package erro

import (
	"errors"
)

var (
	ErrStatusUnauthorized 	= errors.New("Invalid Token")
	ErrTokenExpired		 	= errors.New("Token expired")
	ErrBadRequest		 	= errors.New("Internal error")
	ErrUnmarshal			= errors.New("Erro Unmarshall")
	ErrMethodNotAllowed		= errors.New("Method not allowed")
	ErrOpenDatabase 		= errors.New("Open Database error")
	ErrQuery 				= errors.New("Query error")
	ErrPreparedQuery 		= errors.New("Prepare dynamo query erro")
	ErrNotFound 			= errors.New("Data not found")
	ErrInsert 				= errors.New("Insert Error")
	ErrList					= errors.New("List Error")
	ErrQueryEmpty			= errors.New("Query parameters missing")
	ErrTokenStillValid		= errors.New("Token is still valid")
)