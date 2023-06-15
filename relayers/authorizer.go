package main

import (
	"math/big"

	ethereum_common "github.com/ethereum/go-ethereum/common"
)

// TODO: Authorizers currently do not generate burn permissions on Ethereal NFTs. This is because we
// want to, in the long term, support arbitrary conditions on burnability, but it is too early for us
// to spend a lot of time thinking about the right interface to determine whether or not burning is allowed.
// Probably the right way to support burn will be to add BurnValidator structs (Validator really is a CreateValidator).
type Authorizer interface {
	ConfigureFromEnv() error
	Address() (ethereum_common.Address, error)
	CreatePayload(recipient ethereum_common.Address, tokenID, sourceID, sourceTokenID, liveUntil big.Int, metadataURI string) ([]byte, error)
	CreateSignature(recipient ethereum_common.Address, tokenID, sourceID, sourceTokenID, liveUntil big.Int, metadataURI string) ([]byte, error)
}
