package authserv

import (
	"fmt"
	"log"

	"gopkg.in/resty.v1"
)

// Get permite realizar una peticion Get a las API de autenticacion.
func Get(endpoint string) {
	resp, err := resty.R().Get(endpoint)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	fmt.Printf("\nError: %v", err)
	fmt.Printf("\nResponse Status Code: %v", resp.StatusCode())
	fmt.Printf("\nResponse Status: %v", resp.Status())
	fmt.Printf("\nResponse Time: %v", resp.Time())
	fmt.Printf("\nResponse Received At: %v", resp.ReceivedAt())
	fmt.Printf("\nResponse Body: %v", resp)
}
