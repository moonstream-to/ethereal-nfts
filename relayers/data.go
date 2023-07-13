package main

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

var ZERO_ADDRESS = common.BigToAddress(big.NewInt(0))

var ErrUnauthorizedRequest error = errors.New("unauthorized request")

type PingResponse struct {
	Status string `json:"status"`
}

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
	AuthorizationMessage interface{} `json:"authorizationMessage"`
}

type ValidateResponse struct {
	Request *AuthorizationRequest `json:"request"`
	Valid   bool                  `json:"valid"`
}

type AuthorizationResponse struct {
	Request           *AuthorizationRequest `json:"request"`
	CreateMessageHash string                `json:"createMessageHash"`
	Signer            string                `json:"signer"`
	Signature         string                `json:"signature"`
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

	r.AuthorizationMessage = request.AuthorizationMessage

	return nil
}
