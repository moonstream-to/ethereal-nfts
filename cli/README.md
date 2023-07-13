# Ethereal CLI

## Deployer workflow

Deploy deployer:

```bash
ethereal-nfts deployer deploy \
    --network mainnet \
    --address <source_contract_address_with_original_NFT> \
    --sender <path_to_keystore_file>
```

```bash
EtherealDeployer deployed at: <ethereal_deployer_address>
```

Deploy basic Ethereal contract:

```bash
ethereal-nfts deployer deploy-basic-ethereal \
    --network mainnet \
    --address <ethereal_deployer_address> \
    --sender <path_to_keystore_file> \
    --name-arg "<chilly_name>" \
    --symbol-arg "<CHILLY>" \
    --owner <address_of_relayers_server>
```

Get basic Ethereal contract address:

```bash
ethereal-nfts deployer get-basic-ethereal-address \
    --network mainnet \
    --address <ethereal_deployer_address> \
    --name-arg "<chilly_name>" \
    --symbol-arg "<CHILLY>"
```

## Basic contract workflow

Mint Ethereal NFT:

```bash
ethereal-nfts basic create \
    --network mainnet\
    --address <address_of_basic_ethereal_contract> \
    --sender <path_to_keystore_file> \
    --recipient <address_of_token_recipient> \
    --token-id 10 \
    --source-id $(python -c "print(<source_contract_address_with_original_NFT>)") \
    --source-token-id 11 \
    --live-until 1708700800 \
    --metadata-uri "<URI_to_token_metadata>" \
    --signer-arg <address_of_relayers_server> \
    --signature "<signature_for_Ethereal_NFT_mint>"
```
