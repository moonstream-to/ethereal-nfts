package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

/**
TODO:
- [ ] Validate should take an EIP712 message and signature, and verify that the signature is valid and that the signer is the owner of the source token.
- [ ] Write Payload function, which calculates the EIP712 message hash for Ethereal creation.
- [x] Write code which loads signing account into the ERC721Relayer
- [ ] Write Authorize, which signs a valid payload (it will do the validation check before authorizing).
*/

type ERC721Relayer struct {
	HTTPProviderURL string
	Web3Client      *ethclient.Client
	ChainID         *big.Int
	privateKey      *ecdsa.PrivateKey
	address         common.Address
}

type ERC721RelayerStatus struct {
	ChainID     *big.Int `json:"chainID"`
	BlockNumber uint64   `json:"blockNumber"`
}

type ERC721RelayerValidateRequest struct {
	Recipient            string `json:"recipient"`
	TokenID              string `json:"tokenID"`
	SourceID             string `json:"sourceID"`
	SourceTokenID        string `json:"sourceTokenID"`
	LiveUntil            string `json:"liveUntil"`
	MetadataURI          string `json:"metadataURI"`
	AuthorizationRequest string `json:"authorizationRequest"`
}

type ERC721RelayerValidateResponse struct {
	Request *ERC721RelayerValidateRequest `json:"request"`
	Valid   bool                          `json:"valid"`
}

func (relayer *ERC721Relayer) ConfigureFromEnv() error {
	relayer.HTTPProviderURL = os.Getenv("RELAYERS_ERC721_HTTP_PROVIDER_URL")
	if relayer.HTTPProviderURL == "" {
		return errors.New("RELAYERS_ERC721_HTTP_PROVIDER_URL must be set")
	}

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

	relayer.privateKey, err = SigningKeyFromEnv()
	if err != nil {
		return err
	}

	relayer.address = crypto.PubkeyToAddress(relayer.privateKey.PublicKey)

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
	return relayer.address, nil
}

func (relayer *ERC721Relayer) Validate(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI, authorization_request string) (bool, error) {
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

	fmt.Printf("Token ID: %s\n", tokenID.String())
	fmt.Printf("Source Token Address: %s\n", contractAddress.Hex())
	fmt.Printf("Source Token ID: %s\n", sourceTokenID.String())
	fmt.Printf("Live Until: %s\n", liveUntil.String())

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
	var requestParameters ERC721RelayerValidateRequest

	bodyDecoder := json.NewDecoder(r.Body)
	decodeErr := bodyDecoder.Decode(&requestParameters)
	if decodeErr != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	recipient := common.HexToAddress(requestParameters.Recipient)

	tokenID, parseOK := new(big.Int).SetString(requestParameters.TokenID, 0)
	if !parseOK {
		http.Error(w, fmt.Sprintf("Error parsing tokenID: %s", requestParameters.TokenID), http.StatusBadRequest)
		return
	}

	sourceID, parseOK := new(big.Int).SetString(requestParameters.SourceID, 0)
	if !parseOK {
		http.Error(w, fmt.Sprintf("Error parsing sourceID: %s", requestParameters.SourceID), http.StatusBadRequest)
		return
	}

	sourceTokenID, parseOK := new(big.Int).SetString(requestParameters.SourceTokenID, 0)
	if !parseOK {
		http.Error(w, fmt.Sprintf("Error parsing sourceTokenID: %s", requestParameters.SourceTokenID), http.StatusBadRequest)
		return
	}

	liveUntil, parseOK := new(big.Int).SetString(requestParameters.LiveUntil, 0)
	if !parseOK {
		http.Error(w, fmt.Sprintf("Error parsing liveUntil: %s", requestParameters.LiveUntil), http.StatusBadRequest)
		return
	}

	valid, validationErr := relayer.Validate(recipient, tokenID, sourceID, sourceTokenID, liveUntil, requestParameters.MetadataURI, requestParameters.AuthorizationRequest)
	if validationErr != nil {
		fmt.Println(validationErr.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := ERC721RelayerValidateResponse{
		Request: &requestParameters,
		Valid:   valid,
	}

	responseJSON, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(responseJSON)
}

func (relayer *ERC721Relayer) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	statusJSON, err := relayer.Status()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(statusJSON)
}
