package protocol

import (
	"log"

	"gitlab.com/jlmanriquez/radius_server/authserv"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type chapProcess struct{}

// NewCHAP la implementacion encargada de procesar el protocolo CHAP
func newCHAP() process {
	return &chapProcess{}
}

func (p *chapProcess) otp(r *radius.Request) *radius.Packet {
	username := rfc2865.UserName_GetString(r.Packet)
	challenge := rfc2865.CHAPPassword_GetString(r.Packet)

	service := authserv.New()
	resp := service.OTP(username, challenge)
	if !resp.ResponseOk || !resp.Authenticated {
		log.Print("[CHAP] OTP incorrectos")
		return r.Response(radius.CodeAccessReject)
	}

	return r.Response(radius.CodeAccessAccept)
}

func (p *chapProcess) login(r *radius.Request) *radius.Packet {
	id := r.Packet.Identifier
	username := rfc2865.UserName_GetString(r.Packet)
	chapChallenge := rfc2865.CHAPChallenge_Get(r.Packet)
	chapPassword := rfc2865.CHAPPassword_Get(r.Packet)

	service := authserv.New()
	resp := service.LoginByCHAP(chapPassword, id, username, chapChallenge)
	if !resp.ResponseOk || !resp.Authenticated {
		log.Printf("[CHAP] CHAP-Password incorrecto")
		return r.Response(radius.CodeAccessReject)
	}

	// Se requiere autenticar mediante OTP
	if resp.OTPRequired {
		return generateOTPChallengePacket(r)
	}

	return r.Response(radius.CodeAccessAccept)
}
