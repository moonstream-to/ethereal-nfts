package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

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
	// CreatePayload(address recipient,uint256 tokenId,uint256 sourceId,uint256 sourceTokenId,uint256 liveUntil,string metadataURI)

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
