package main

import (
	"fmt"
	"net/http"
)

func CreateServer(bindAddress string) (*http.Server, error) {
	var server *http.Server

	validator := ERC721Validator{}
	validatorConfigurationErr := validator.ConfigureFromEnv()
	if validatorConfigurationErr != nil {
		return server, validatorConfigurationErr
	}

	mux := http.NewServeMux()

	// Validator endpoints:
	// - /validator/status
	// - /validator/validate
	//
	// Authorizer endpoints:
	// - /authorizer/status
	//
	// Relayer endpoints:
	// - /status
	// - /authorize

	mux.HandleFunc("/validator/status", func(w http.ResponseWriter, r *http.Request) {
		statusJSON, err := validator.Status()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, _ = w.Write(statusJSON)
	})

	server = &http.Server{
		Addr:    bindAddress,
		Handler: mux,
	}

	return server, nil
}

func RunServer(bindAddress string) error {
	server, serverCreationError := CreateServer(bindAddress)
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
