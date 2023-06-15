package main

import (
	"fmt"
	"net/http"
)

func CreateServer(relayerType, bindAddress string) (*http.Server, error) {
	var server *http.Server
	var relayer Relayer

	switch relayerType {
	case "erc721":
		relayer = &ERC721Relayer{}
	default:
		return server, fmt.Errorf("unknown relayer type: %s", relayerType)
	}

	relayerConfigurationErr := relayer.ConfigureFromEnv()
	if relayerConfigurationErr != nil {
		return server, relayerConfigurationErr
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/status", relayer.StatusHandler)
	mux.HandleFunc("/address", relayer.AddressHandler)
	mux.HandleFunc("/validate", relayer.ValidateHandler)
	mux.HandleFunc("/create_message_hash", relayer.CreateMessageHashHandler)
	mux.HandleFunc("/authorize", relayer.AuthorizeHandler)

	server = &http.Server{
		Addr:    bindAddress,
		Handler: mux,
	}

	return server, nil
}

func RunServer(relayerType, bindAddress string) error {
	if bindAddress == "" {
		bindAddress = ":3743"
	}
	server, serverCreationError := CreateServer(relayerType, bindAddress)
	if serverCreationError != nil {
		return serverCreationError
	}

	fmt.Printf("Starting server on: %s\n", bindAddress)
	err := server.ListenAndServe()
	if err != nil {
		return err
	}

	return nil
}
