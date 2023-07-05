# Ethereal Relayers

## Package structure

```
.
|- main.go - CLI definition and entrypoint into the codebase.
|- server.go - Definition of relayer API server (routes, CORS, etc.).
|- relayer.go - Relayer interface.
|- data.go - Defines commonly used data containers (e.g. for API requests and responses). Also defines utilities for working with these containers.
|- create.go - Defines EIP712 (https://eips.ethereum.org/EIPS/eip-712) message structure for creation of Ethereal NFTs.
|- erc721_relayer.go - ERC721 relayer implementation.
|- loopring_relayer.go - Loopring relayer implementation.
```
