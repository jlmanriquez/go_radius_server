package authserv

import (
	"bytes"
	"crypto/md5"
)

// Response encapsula la informacion de las respuestas
// de los servicios REST de Service.
type Response struct {
	ResponseOk      bool
	ResponseMessage string
	Authenticated   bool
	OTPRequired     bool
	Challenge       []byte
}

// Service es una interfaz con las funcionalidades que el
// connector RADIUS debera utilizar para consumir la
// API Rest de servicio de autenticacion.
type Service interface {
	Login(username, password string) Response
	LoginByCHAP(chapPassword []byte, id byte, username string, authChallenge []byte) Response
	OTP(username string, otp string) Response
}

type apiImpl struct{}

const (
	validUsername = "test"
	validPassword = "test"
)

// New retorna una implementacion del servicio de negocio.
func New() Service {
	return &apiImpl{}
}

func (a *apiImpl) Login(username, password string) Response {
	if username != validUsername || password != validPassword {
		return Response{
			ResponseOk:      true,
			ResponseMessage: "Usuario/Password incorrectos",
			Authenticated:   false,
			OTPRequired:     false,
		}
	}

	return Response{
		ResponseOk:      true,
		ResponseMessage: "",
		Authenticated:   true,
		OTPRequired:     true,
	}
}

// LoginByCHAP realiza la autenticacion validando el CHAP-Password enviado desde el cliente.
func (a *apiImpl) LoginByCHAP(chapPassword []byte, id byte, username string, authChallenge []byte) Response {
	hash := md5.New()
	hash.Write([]byte{id})
	hash.Write([]byte(getPasswordByUsername(username)))
	hash.Write([]byte(authChallenge))

	generatedPassword := []byte{id}
	generatedPassword = append(generatedPassword, hash.Sum(nil)[:16]...)

	return Response{
		ResponseOk:      true,
		ResponseMessage: "",
		Authenticated:   bytes.Equal(chapPassword, generatedPassword),
		OTPRequired:     true,
	}
}

func (a *apiImpl) OTP(username string, otp string) Response {
	// TODO ...se validara el chapChallenge...

	return Response{
		ResponseOk:      true,
		ResponseMessage: "",
		Authenticated:   true,
		Challenge:       []byte{},
	}
}

func getPasswordByUsername(username string) string {
	return "test"
}
