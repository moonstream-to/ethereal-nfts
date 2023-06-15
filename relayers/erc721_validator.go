package main

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethereum_common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type ERC721Validator struct {
	HTTPProviderURL string
	Web3Client      *ethclient.Client
	ChainID         *big.Int
}

type ERC721ValidatorStatus struct {
	HTTPProviderURL string   `json:"httpProviderURL"`
	ChainID         *big.Int `json:"chainID"`
	BlockNumber     uint64   `json:"blockNumber"`
}

func (validator *ERC721Validator) ConfigureFromEnv() error {
	validator.HTTPProviderURL = os.Getenv("ERC721_VALIDATOR_HTTP_PROVIDER_URL")

	client, err := ethclient.Dial(validator.HTTPProviderURL)
	if err != nil {
		return err
	}
	validator.Web3Client = client

	// eth_chainId returns the chain ID (in hex format) used for transaction signing at the current best block
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return err
	}

	validator.ChainID = chainID

	return nil
}

func (validator *ERC721Validator) Status() ([]byte, error) {
	// eth_blockNumber returns the number of most recent block
	blockNumber, err := validator.Web3Client.BlockNumber(context.Background())
	if err != nil {
		return []byte{}, err
	}

	status := ERC721ValidatorStatus{
		HTTPProviderURL: validator.HTTPProviderURL,
		ChainID:         validator.ChainID,
		BlockNumber:     blockNumber,
	}

	statusJSON, marshalErr := json.Marshal(status)
	if marshalErr != nil {
		return []byte{}, marshalErr
	}

	return statusJSON, nil
}

func (validator *ERC721Validator) Validate(recipient ethereum_common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorization_request string) (bool, error) {
	if sourceID.Cmp(big.NewInt(0)) <= 0 {
		return false, errors.New("sourceID must be greater than zero")
	}
	if sourceTokenID.Cmp(big.NewInt(0)) <= 0 {
		return false, errors.New("sourceTokenID must be greater than zero")
	}
	if tokenID.Cmp(big.NewInt(0)) <= 0 {
		return false, errors.New("tokenID must be greater than zero")
	}
	if liveUntil.Cmp(big.NewInt(0)) <= 0 {
		return false, errors.New("liveUntil must be greater than zero")
	}

	contractAddress := ethereum_common.BigToAddress(sourceID)
	contract, contractErr := NewERC721Contract(contractAddress, validator.Web3Client)
	if contractErr != nil {
		return false, contractErr
	}

	callOpts := &bind.CallOpts{Pending: false}

	owner, callErr := contract.OwnerOf(callOpts, sourceTokenID)
	if callErr != nil {
		return false, callErr
	}

	return recipient == owner, nil
}
