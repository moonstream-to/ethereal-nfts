package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

/**
TODO:
- [ ] Validate should take an EIP712 message and signature, and verify that the signature is valid and that the signer is the owner of the source token.
- [x] Write CreateMessageHash function, which calculates the EIP712 message hash for Ethereal creation.
- [x] Write code which loads signing account into the ERC721Relayer
- [x] Write Authorize, which signs a valid payload (it will do the validation check before authorizing).
*/

var ERC721RelayerDomainName string = "ethereal-relayers-erc721"

var ERC721RelayerAuthorizationPayload []apitypes.Type = []apitypes.Type{
	{Name: "recipient", Type: "address"},
	{Name: "tokenId", Type: "uint256"},
	{Name: "sourceId", Type: "uint256"},
	{Name: "sourceTokenId", Type: "uint256"},
	{Name: "liveUntil", Type: "uint256"},
	{Name: "metadataURI", Type: "string"},
	{Name: "authorizeBefore", Type: "uint256"},
}

type ERC721Relayer struct {
	HTTPProviderURL         string
	Web3Client              *ethclient.Client
	SourceChainID           *big.Int
	privateKey              *ecdsa.PrivateKey
	address                 common.Address
	EtherealContractAddress common.Address
	EtherealChainID         *big.Int
}

type ERC721RelayerStatus struct {
	SourceChainID           *big.Int       `json:"chainID"`
	BlockNumber             uint64         `json:"blockNumber"`
	EtherealContractAddress common.Address `json:"etherealContractAddress"`
	EtherealChainID         *big.Int       `json:"etherealChainID"`
}

type ERC721RelayerAuthorizationMessage struct {
	AuthorizeBefore int64 `json:"authorizeBefore"`
	// This signature is expected to include the JSON-represented CreateMessageHashRequest along with the additional "signBefore".
	Signature []byte `json:"signature"`
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

	relayer.SourceChainID = chainID

	relayer.privateKey, err = SigningKeyFromEnv()
	if err != nil {
		return err
	}

	relayer.address = crypto.PubkeyToAddress(relayer.privateKey.PublicKey)

	var zeroAddress common.Address

	etherealAddressRaw := os.Getenv("RELAYERS_ETHEREAL_ADDRESS")
	relayer.EtherealContractAddress = common.HexToAddress(etherealAddressRaw)
	if relayer.EtherealContractAddress.Hex() == zeroAddress.Hex() {
		return fmt.Errorf("RELAYERS_ETHEREAL_ADDRESS must be set to a non-zero Ethereum address")
	}

	etherealChainIDRaw := os.Getenv("RELAYERS_ETHEREAL_CHAIN_ID")
	if etherealAddressRaw == "" {
		return errors.New("RELAYERS_ETHEREAL_CHAIN_ID must be set")
	}
	var etherealChainIDParsed bool
	relayer.EtherealChainID, etherealChainIDParsed = new(big.Int).SetString(etherealChainIDRaw, 0)
	if !etherealChainIDParsed {
		return fmt.Errorf("RELAYERS_ETHEREAL_CHAIN_ID must be a valid integer, got %s", etherealChainIDRaw)
	}

	return nil
}

func (relayer *ERC721Relayer) Status() ([]byte, error) {
	// eth_blockNumber returns the number of most recent block
	blockNumber, err := relayer.Web3Client.BlockNumber(context.Background())
	if err != nil {
		return []byte{}, err
	}

	status := ERC721RelayerStatus{
		SourceChainID:           relayer.SourceChainID,
		BlockNumber:             blockNumber,
		EtherealContractAddress: relayer.EtherealContractAddress,
		EtherealChainID:         relayer.EtherealChainID,
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

func (relayer *ERC721Relayer) Validate(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorizationMessage interface{}) (bool, error) {
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

	parsedAuthorizationMessage := authorizationMessage.(ERC721RelayerAuthorizationMessage)

	messageHash, hashErr := ERC721AuthorizationPayloadHash(relayer.SourceChainID, recipient, tokenID, sourceID, sourceTokenID, liveUntil, metadataURI, parsedAuthorizationMessage.AuthorizeBefore)

	if hashErr != nil {
		return false, hashErr
	}

	signerPubkey, recoverErr := crypto.SigToPub(messageHash, parsedAuthorizationMessage.Signature)
	if recoverErr != nil {
		return false, recoverErr
	}

	signerAddress := crypto.PubkeyToAddress(*signerPubkey)

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

	return signerAddress == owner, nil
}

func (relayer *ERC721Relayer) CreateMessageHash(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string) ([]byte, error) {
	return CreateMessageHash(recipient, tokenID, sourceID, sourceTokenID, liveUntil, metadataURI, relayer.EtherealChainID, relayer.EtherealContractAddress)
}

func (relayer *ERC721Relayer) Authorize(recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorizationMessage interface{}) ([]byte, error) {
	valid, validationErr := relayer.Validate(recipient, tokenID, sourceID, sourceTokenID, liveUntil, metadataURI, authorizationMessage)
	if validationErr != nil {
		return []byte{}, validationErr
	}
	if !valid {
		return []byte{}, ErrUnauthorizedRequest
	}

	messageHash, messageHashErr := relayer.CreateMessageHash(recipient, tokenID, sourceID, sourceTokenID, liveUntil, metadataURI)
	if messageHashErr != nil {
		return []byte{}, messageHashErr
	}

	signature, err := SignRawMessage(messageHash, relayer.privateKey, false)

	return signature, err
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
	var requestParameters AuthorizationRequest

	bodyDecoder := json.NewDecoder(r.Body)
	decodeErr := bodyDecoder.Decode(&requestParameters)
	if decodeErr != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	parameters := &RelayerFunctionParameters{}
	parseErr := parameters.ParseAuthorizationRequest(&requestParameters)
	if parseErr != nil {
		http.Error(w, parseErr.Error(), http.StatusBadRequest)
		return
	}

	valid, validationErr := relayer.Validate(parameters.Recipient, parameters.TokenID, parameters.SourceID, parameters.SourceTokenID, parameters.LiveUntil, parameters.MetadataURI, parameters.AuthorizationMessage)
	if validationErr != nil {
		fmt.Println(validationErr.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := ValidateResponse{
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

func (relayer *ERC721Relayer) CreateMessageHashHandler(w http.ResponseWriter, r *http.Request) {
	var requestParameters CreateMessageHashRequest

	bodyDecoder := json.NewDecoder(r.Body)
	decodeErr := bodyDecoder.Decode(&requestParameters)
	if decodeErr != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	parameters := &RelayerFunctionParameters{}
	parseErr := parameters.ParseCreateMessageHashRequest(&requestParameters)
	if parseErr != nil {
		http.Error(w, parseErr.Error(), http.StatusBadRequest)
		return
	}

	messageHash, messageHashErr := relayer.CreateMessageHash(parameters.Recipient, parameters.TokenID, parameters.SourceID, parameters.SourceTokenID, parameters.LiveUntil, parameters.MetadataURI)
	if messageHashErr != nil {
		fmt.Println(messageHashErr.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(hex.EncodeToString(messageHash)))
}

func (relayer *ERC721Relayer) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	var requestParameters AuthorizationRequest

	bodyDecoder := json.NewDecoder(r.Body)
	decodeErr := bodyDecoder.Decode(&requestParameters)
	if decodeErr != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	parameters := &RelayerFunctionParameters{}
	parseErr := parameters.ParseAuthorizationRequest(&requestParameters)
	if parseErr != nil {
		http.Error(w, parseErr.Error(), http.StatusBadRequest)
		return
	}

	signature, authorizationErr := relayer.Authorize(parameters.Recipient, parameters.TokenID, parameters.SourceID, parameters.SourceTokenID, parameters.LiveUntil, parameters.MetadataURI, parameters.AuthorizationMessage)
	if authorizationErr != nil {
		fmt.Println(authorizationErr.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := AuthorizationResponse{
		Request:   &requestParameters,
		Signer:    relayer.address.Hex(),
		Signature: hex.EncodeToString(signature),
	}

	responseJSON, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(responseJSON)
}

func ERC721AuthorizationPayloadHash(chainID *big.Int, recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorizeBefore int64) ([]byte, error) {
	data := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain":         EIP712Domain,
			"AuthorizationPayload": ERC721RelayerAuthorizationPayload,
		},
		PrimaryType: "AuthorizationPayload",
		Domain: apitypes.TypedDataDomain{
			Name: ERC721RelayerDomainName,
			// Note: Retain same version as rest of codebase!
			Version: EIP712DomainVersion,
			ChainId: (*math.HexOrDecimal256)(chainID),
		},
		Message: apitypes.TypedDataMessage{
			"recipient":       recipient.Hex(),
			"tokenId":         tokenID.String(),
			"sourceId":        sourceID.String(),
			"sourceTokenId":   sourceTokenID.String(),
			"liveUntil":       liveUntil.String(),
			"metadataURI":     metadataURI,
			"authorizeBefore": authorizeBefore,
		},
	}

	messageHash, _, hashErr := apitypes.TypedDataAndHash(data)
	return messageHash, hashErr
}

func ERC721SignAuthorizationPayload(keystoreFile string, chainID *big.Int, recipient common.Address, tokenID, sourceID, sourceTokenID, liveUntil *big.Int, metadataURI string, authorizeBefore int64) ([]byte, error) {
	messageHash, hashErr := ERC721AuthorizationPayloadHash(chainID, recipient, tokenID, sourceID, sourceTokenID, liveUntil, metadataURI, authorizeBefore)
	if hashErr != nil {
		return []byte{}, hashErr
	}

	privateKey, privateKeyErr := PrivateKeyFromKeystoreFile(keystoreFile, "", true)
	if privateKeyErr != nil {
		return []byte{}, privateKeyErr
	}

	signature, err := SignRawMessage(messageHash, privateKey, false)

	return signature, err
}
