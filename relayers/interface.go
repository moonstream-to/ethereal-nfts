package main

import (
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
)

type AddressResponse struct {
	Address string `json:"address"`
}

type Relayer interface {
	ConfigureFromEnv() error
	Status() ([]byte, error)
	Address() (common.Address, error)
	Validate(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorization_request string) (bool, error)
	Payload(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil big.Int, metadataURI string) ([]byte, error)
	Authorize(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil big.Int, metadataURI string) ([]byte, error)

	StatusHandler(w http.ResponseWriter, r *http.Request)
	AddressHandler(w http.ResponseWriter, r *http.Request)
	ValidateHandler(w http.ResponseWriter, r *http.Request)
	AuthorizeHandler(w http.ResponseWriter, r *http.Request)
}
