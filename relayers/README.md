# Ethereal Relayers

## Architecture

![Relayer architecture](https://github.com/moonstream-to/ethereal-nfts/assets/8016073/f5fa3d9f-6733-4ce4-ab45-dbd82a754557)

## Package structure

```
.
|- main.go - CLI definition and entrypoint into the codebase.
|- server.go - Definition of relayer API server (routes, CORS, etc.).
|- relayer.go - Relayer interface.
|- data.go - Defines commonly used data containers (e.g. for API requests and responses). Also defines utilities for working with these containers.
|- create.go - Defines EIP712 (https://eips.ethereum.org/EIPS/eip-712) message structure for creation of Ethereal NFTs.
|- erc721.go - Go interface to ERC721 contracts, generated using abigen (https://github.com/ethereum/go-ethereum).
|- erc721_relayer.go - ERC721 relayer implementation.
|- loopring_relayer.go - Loopring relayer implementation.
```

## ERC721 - Authorization workflow

Generate authorization message for an ERC721 source contract:

```bash
relayers authorization erc721 \
    --source-id <source_contract_address_with_original_NFT> \
    --chain-id 1 \
    --destination <address_of_base_Ethereal_contract> \
    --keystore <path_to_keystore_file> \
    --live-until 1708700800 \
    --metadata-uri "<URI_to_token_metadata>" \
    --recipient <address_which_can_mint_the_Ethereal_NFT> \
    --source-token-id 10 \
    --authorize-before 1708700801
```

Example of output:

```bash
Signature: <signature_for_relayer>
```

Authorize with Relayer server to be able mint the Ethereal NFT:

```bash
curl http://127.0.0.1:3743/authorize \
    --data '{
        "recipient": "<address_which_can_mint_the_Ethereal_NFT>",
        "tokenID": "11",
        "sourceID": "<source_contract_address_with_original_NFT>",
        "sourceTokenID": "10",
        "liveUntil": "1708700800",
        "metadataURI": "<URI_to_token_metadata>",
        "authorizationMessage": {
            "authorizeBefore": 1708700801,
            "signature": "<signature_for_relayer>"
        }
    }' \
    --header "Content-Type: application/json"
```

Example of output:

```json
{
  "request": {
    "recipient": "<address_which_can_mint_the_Ethereal_NFT>",
    "tokenID": "11",
    "sourceID": "<source_contract_address_with_original_NFT>",
    "sourceTokenID": "10",
    "liveUntil": "1688700800",
    "metadataURI": "<URI_to_token_metadata>",
    "authorizationMessage": {
      "authorizeBefore": 1688700800,
      "signature": "<signature_for_relayer>"
    }
  },
  "createMessageHash": "<create_message_hash>",
  "signer": "<address_of_relayer_signed_the_message>",
  "signature": "<signature_for_Ethereal_NFT_mint>"
}
```
