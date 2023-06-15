package main

import (
	"math/big"

	ethereum_common "github.com/ethereum/go-ethereum/common"
)

type Validator interface {
	ConfigureFromEnv() error
	Status() ([]byte, error)
	Validate(recipient ethereum_common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorization_request string) (bool, error)
}
