package protocol

import (
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func generateOTPChallengePacket(r *radius.Request, message ...string) *radius.Packet {
	response := r.Response(radius.CodeAccessChallenge)
	response.Add(rfc2865.State_Type, radius.Attribute([]byte("1")))

	if len(message) > 0 {
		response.Add(rfc2865.ReplyMessage_Type, radius.Attribute(message[0]))
	}

	return response
}
