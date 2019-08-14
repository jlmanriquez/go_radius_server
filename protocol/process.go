package protocol

import (
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// Type representa el tipo de procesos de protocolos soportados
type Type int

const (
	unknowType Type = iota
	// ProcessCHAP es el tipo de proceso para protocolo CHAP
	processCHAP
	// ProcessPAP es el tipo de proceso para protocolo PAP
	processPAP
)

const (
	loginState = "0"
	otpState   = "1"
)

// Process interfaz que expone los metodos requeridos para
// el procesamiento de un protocolo RADIUS.
type process interface {
	login(r *radius.Request) *radius.Packet
	otp(r *radius.Request) *radius.Packet
}

// ProcessRequest delega el procesamiento de la request dependiendo
// del protocolo PAP/CHAP en su respectiva implementacion.
func ProcessRequest(r *radius.Request) *radius.Packet {
	theProcess := getProcessByProtocol(r.Packet)

	// Dependiendo del estado se conoce si se debe realizar Login o OTP
	state := rfc2865.State_GetString(r.Packet)

	// Se esta solicitando autenticacion mediante Login
	if state != otpState {
		return theProcess.login(r)
	}

	// Se esta solicitando validacion de OTP
	return theProcess.otp(r)
}

func getProcessByProtocol(p *radius.Packet) process {
	chapChallenge := rfc2865.CHAPChallenge_GetString(p)

	// Si CHAP-Challenge no viene informado, corresponde a una
	// peticion PAP/PPP. Caso contrario CHAP/PPP.
	if chapChallenge == "" {
		return newPAP()
	}

	return newCHAP()
}
