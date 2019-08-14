package main

import (
	"log"

	"gitlab.com/jlmanriquez/radius_server/protocol"

	"layeh.com/radius"
)

func main() {
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		respPacket := protocol.ProcessRequest(r)

		log.Printf("Writing %v to %v", respPacket.Code, r.RemoteAddr)
		log.Println("--------------------------------------------")
		w.Write(respPacket)
	}

	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(`secret`)),
	}

	log.Printf("Starting server on :1812")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
