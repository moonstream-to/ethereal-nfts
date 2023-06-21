package main

import (
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

var ErrUnauthorizedRequest error = errors.New("unauthorized request")

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

type AuthorizationRequest struct {
	CreateMessageHashRequest
	AuthorizationRequest interface{} `json:"authorizationRequest"`
}

type ValidateResponse struct {
	Request *AuthorizationRequest `json:"request"`
	Valid   bool                  `json:"valid"`
}

type AuthorizationResponse struct {
	Request   *AuthorizationRequest `json:"request"`
	Signer    string                `json:"signer"`
	Signature string                `json:"signature"`
}

type Relayer interface {
	ConfigureFromEnv() error
	Status() ([]byte, error)
	Address() (common.Address, error)
	Validate(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorizationMessage interface{}) (bool, error)
	CreateMessageHash(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string) ([]byte, error)
	Authorize(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorizationRequest interface{}) ([]byte, error)

	StatusHandler(w http.ResponseWriter, r *http.Request)
	AddressHandler(w http.ResponseWriter, r *http.Request)
	ValidateHandler(w http.ResponseWriter, r *http.Request)
	CreateMessageHashHandler(w http.ResponseWriter, r *http.Request)
	AuthorizeHandler(w http.ResponseWriter, r *http.Request)
}

type RelayerFunctionParameters struct {
	Recipient            common.Address
	TokenID              *big.Int
	SourceID             *big.Int
	SourceTokenID        *big.Int
	LiveUntil            *big.Int
	MetadataURI          string
	AuthorizationMessage interface{}
}

func (r *RelayerFunctionParameters) ParseCreateMessageHashRequest(request *CreateMessageHashRequest) error {
	recipient := common.HexToAddress(request.Recipient)

	tokenID, parseOK := new(big.Int).SetString(request.TokenID, 0)
	if !parseOK {
		return fmt.Errorf("Error parsing tokenID: %s", request.TokenID)
	}

	sourceID, parseOK := new(big.Int).SetString(request.SourceID, 0)
	if !parseOK {
		return fmt.Errorf("Error parsing sourceID: %s", request.SourceID)
	}

	sourceTokenID, parseOK := new(big.Int).SetString(request.SourceTokenID, 0)
	if !parseOK {
		return fmt.Errorf("Error parsing sourceTokenID: %s", request.SourceTokenID)
	}

	liveUntil, parseOK := new(big.Int).SetString(request.LiveUntil, 0)
	if !parseOK {
		return fmt.Errorf("Error parsing liveUntil: %s", request.LiveUntil)
	}

	r.Recipient = recipient
	r.TokenID = tokenID
	r.SourceID = sourceID
	r.SourceTokenID = sourceTokenID
	r.LiveUntil = liveUntil
	r.MetadataURI = request.MetadataURI

	return nil
}

func (r *RelayerFunctionParameters) ParseAuthorizationRequest(request *AuthorizationRequest) error {
	if err := r.ParseCreateMessageHashRequest(&request.CreateMessageHashRequest); err != nil {
		return err
	}

	r.AuthorizationMessage = request.AuthorizationRequest

	return nil
}

var EIP712Domain []apitypes.Type = []apitypes.Type{
	{Name: "name", Type: "string"},
	{Name: "version", Type: "string"},
	{Name: "chainId", Type: "uint256"},
	{Name: "verifyingContract", Type: "address"},
}

var CreatePayload []apitypes.Type = []apitypes.Type{
	{Name: "recipient", Type: "address"},
	{Name: "tokenId", Type: "uint256"},
	{Name: "sourceId", Type: "uint256"},
	{Name: "sourceTokenId", Type: "uint256"},
	{Name: "liveUntil", Type: "uint256"},
	{Name: "metadataURI", Type: "string"},
}

// These are meant to match the current version of the EIP712 domain in ../contracts/Ethereal.sol (see Ethereal constructor).
var EIP712DomainName = "ethereal"
var EIP712DomainVersion = "0.0.1"

func CreateMessageHash(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, chainID *big.Int, verifyingContractAddress common.Address) ([]byte, error) {

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

	messageHash, _, err := apitypes.TypedDataAndHash(data)
	return messageHash, err
}
