package main

import (
	"fmt"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

type AddressResponse struct {
	Address string `json:"address"`
}

type CreateMessageHashRequest struct {
	Recipient     string `json:"recipient"`
	TokenID       string `json:"tokenID"`
	SourceID      string `json:"sourceID"`
	SourceTokenID string `json:"sourceTokenID"`
	LiveUntil     string `json:"liveUntil"`
	MetadataURI   string `json:"metadataURI"`
}

type ValidateRequest struct {
	CreateMessageHashRequest
	AuthorizationRequest string `json:"authorizationRequest"`
}

type ValidateResponse struct {
	Request *ValidateRequest `json:"request"`
	Valid   bool             `json:"valid"`
}

type Relayer interface {
	ConfigureFromEnv() error
	Status() ([]byte, error)
	Address() (common.Address, error)
	Validate(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorization_request string) (bool, error)
	CreateMessageHash(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string) ([]byte, error)
	Authorize(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string) ([]byte, error)

	StatusHandler(w http.ResponseWriter, r *http.Request)
	AddressHandler(w http.ResponseWriter, r *http.Request)
	ValidateHandler(w http.ResponseWriter, r *http.Request)
	CreateMessageHashHandler(w http.ResponseWriter, r *http.Request)
	AuthorizeHandler(w http.ResponseWriter, r *http.Request)
}

var EIP712Domain []apitypes.Type = []apitypes.Type{
	{Name: "name", Type: "string"},
	{Name: "version", Type: "string"},
	{Name: "chainId", Type: "uint256"},
	{Name: "verifyingContract", Type: "address"},
}

// These are meant to match the current version of the EIP712 domain in ../contracts/Ethereal.sol (see Ethereal constructor).
var EIP712DomainName = "ethereal"
var EIP712DomainVersion = "0.0.1"

func CreateMessageHash(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, chainID *big.Int, verifyingContractAddress common.Address) ([]byte, error) {
	var CreatePayload []apitypes.Type = []apitypes.Type{
		{Name: "recipient", Type: "address"},
		{Name: "tokenId", Type: "uint256"},
		{Name: "sourceId", Type: "uint256"},
		{Name: "sourceTokenId", Type: "uint256"},
		{Name: "liveUntil", Type: "uint256"},
		{Name: "metadataURI", Type: "string"},
	}

	fmt.Printf("CreateMessageHash -- recipient = %s, tokenID = %s, sourceID = %s, sourceTokenID = %s, liveUntil = %s, metadataURI = %s, chainID = %s, verifyingContractAddress = %s\n", recipient.Hex(), tokenID.String(), sourceID.String(), sourceTokenID.String(), liveUntil.String(), metadataURI, chainID.String(), verifyingContractAddress.Hex())

	// Inspired by: https://medium.com/alpineintel/issuing-and-verifying-eip-712-challenges-with-go-32635ca78aaf
	data := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain":  EIP712Domain,
			"CreatePayload": CreatePayload,
		},
		PrimaryType: "CreatePayload",
		Domain: apitypes.TypedDataDomain{
			Name:              EIP712DomainName,
			Version:           EIP712DomainVersion,
			ChainId:           (*math.HexOrDecimal256)(chainID),
			VerifyingContract: verifyingContractAddress.Hex(),
		},
		Message: apitypes.TypedDataMessage{
			"recipient":     recipient.Hex(),
			"tokenId":       tokenID.String(),
			"sourceId":      sourceID.String(),
			"sourceTokenId": sourceTokenID.String(),
			"liveUntil":     liveUntil.String(),
			"metadataURI":   metadataURI,
		},
	}

	fmt.Println(data)
	fmt.Println(data.Domain.ChainId)

	messageHash, _, err := apitypes.TypedDataAndHash(data)
	return messageHash, err
}
