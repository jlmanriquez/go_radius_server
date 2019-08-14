package protocol

import (
	"log"

	"gitlab.com/jlmanriquez/radius_server/authserv"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type papProcess struct{}

// NewPAP la implementacion encargada de procesar el protocolo CHAP
func newPAP() process {
	return &papProcess{}
}

func (p *papProcess) login(r *radius.Request) *radius.Packet {
	username := rfc2865.UserName_GetString(r.Packet)
	password := rfc2865.UserPassword_GetString(r.Packet)

	service := authserv.New()
	resp := service.Login(username, password)
	// Se obtuvo respuesta desde API de autenticacion y se verifica que no
	// haya sido autenticado adecuadamente, en este caso se retorna
	// al cliente una respuesta de rechazo.
	if !resp.ResponseOk || !resp.Authenticated {
		log.Printf("No fue pisible autenticar PAP/Login... %s", resp.ResponseMessage)
		return r.Response(radius.CodeAccessReject)
	}

	// Si no es requerida una autenticacion mediante OTP se responde
	// al cliente con codigo de acceso permitido.
	if !resp.OTPRequired {
		log.Print("PAP Finalizado.")
		return r.Response(radius.CodeAccessAccept)
	}

	log.Print("Autenticacion OTP requerida...")
	return generateOTPChallengePacket(r)
}

func (p *papProcess) otp(r *radius.Request) *radius.Packet {
	username := rfc2865.UserName_GetString(r.Packet)
	challenge := rfc2865.UserPassword_GetString(r.Packet)

	service := authserv.New()
	resp := service.OTP(username, challenge)
	if !resp.ResponseOk || !resp.Authenticated {
		log.Printf("No fue pisible autenticar PAP/OTP... %s", resp.ResponseMessage)
		return r.Response(radius.CodeAccessReject)
	}

	return r.Response(radius.CodeAccessAccept)
}
