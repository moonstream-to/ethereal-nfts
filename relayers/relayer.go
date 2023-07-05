package main

import (
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
)

type Relayer interface {
	ConfigureFromEnv() error
	Status() ([]byte, error)
	Address() (common.Address, error)
	Validate(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorizationMessage interface{}) (bool, error)
	CreateMessageHash(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string) ([]byte, error)
	Authorize(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorizationMessage interface{}) ([]byte, error)

	StatusHandler(w http.ResponseWriter, r *http.Request)
	AddressHandler(w http.ResponseWriter, r *http.Request)
	ValidateHandler(w http.ResponseWriter, r *http.Request)
	CreateMessageHashHandler(w http.ResponseWriter, r *http.Request)
	AuthorizeHandler(w http.ResponseWriter, r *http.Request)
}
