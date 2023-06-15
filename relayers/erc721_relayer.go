package main

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type ERC721Relayer struct {
	HTTPProviderURL string
	Web3Client      *ethclient.Client
	ChainID         *big.Int
}

type ERC721RelayerStatus struct {
	ChainID     *big.Int `json:"chainID"`
	BlockNumber uint64   `json:"blockNumber"`
}

func (relayer *ERC721Relayer) ConfigureFromEnv() error {
	relayer.HTTPProviderURL = os.Getenv("RELAYERS_ERC721_HTTP_PROVIDER_URL")

	client, err := ethclient.Dial(relayer.HTTPProviderURL)
	if err != nil {
		return err
	}
	relayer.Web3Client = client

	// eth_chainId returns the chain ID (in hex format) used for transaction signing at the current best block
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return err
	}

	relayer.ChainID = chainID

	return nil
}

func (relayer *ERC721Relayer) Status() ([]byte, error) {
	// eth_blockNumber returns the number of most recent block
	blockNumber, err := relayer.Web3Client.BlockNumber(context.Background())
	if err != nil {
		return []byte{}, err
	}

	status := ERC721RelayerStatus{
		ChainID:     relayer.ChainID,
		BlockNumber: blockNumber,
	}

	statusJSON, marshalErr := json.Marshal(status)
	if marshalErr != nil {
		return []byte{}, marshalErr
	}

	return statusJSON, nil
}

func (relayer *ERC721Relayer) Address() (common.Address, error) {
	return common.Address{}, nil
}

func (relayer *ERC721Relayer) Validate(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorization_request string) (bool, error) {
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

	contractAddress := common.BigToAddress(sourceID)
	contract, contractErr := NewERC721Contract(contractAddress, relayer.Web3Client)
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

func (relayer *ERC721Relayer) Payload(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil big.Int, metadataURI string) ([]byte, error) {
	return []byte{}, nil
}
func (relayer *ERC721Relayer) Authorize(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil big.Int, metadataURI string) ([]byte, error) {
	return []byte{}, nil
}

func (relayer *ERC721Relayer) StatusHandler(w http.ResponseWriter, r *http.Request) {
	statusJSON, err := relayer.Status()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(statusJSON)
}

func (relayer *ERC721Relayer) AddressHandler(w http.ResponseWriter, r *http.Request) {
	address, err := relayer.Address()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := AddressResponse{
		Address: address.Hex(),
	}

	responseJSON, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(responseJSON)
}

func (relayer *ERC721Relayer) ValidateHandler(w http.ResponseWriter, r *http.Request) {
	statusJSON, err := relayer.Status()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(statusJSON)
}

func (relayer *ERC721Relayer) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	statusJSON, err := relayer.Status()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(statusJSON)
}
