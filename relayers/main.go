// Relayers API server and command-line interface.
//
// The github.com/moonstream-to/ethereal-nfts/relayers package is the entrypoint to the libre (free and open source)
// Ethereal NFT relayers tooling. This package defines the structure of the relayers API and also defines
// the command-line interface that can be used to configure and start the API server.
//
// A relayer consists of:
// 1. A validator, which checks that the person requesting creation of an Ethereal matching a given source asset
// is in fact authorized to make this request. For example, an ERC721 validator would check that the person
// requesting Ethereal creation owns the source ERC721 token.
// 2. An authorizer, which signs the creation message for the Ethereal and makes it available to the appropriate
// account to submit as a transaction. For example, this can be done using the Moonstream Metatransaction API:
// https://engineapi.moonstream.to/metatx

// Structure of "relayers" CLI:
// - relayers serve <relayer type>
// - relayers version
// - relayers completion {bash | zsh | fish}

package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/spf13/cobra"
)

const RELAYERS_VERSION string = "0.0.1"

func main() {
	cmd := CreateRootCommand()
	err := cmd.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func CreateRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relayers",
		Short: "Ethereal NFT relayers",
		Long:  `Run a relayer that helps people mint Ethereal NFTs.`,
	}

	versionCmd := CreateVersionCommand()
	serveCmd := CreateServeCommand()
	authorizationCmd := CreateAuthorizationCommand()

	cmd.AddCommand(versionCmd, serveCmd, authorizationCmd)

	return cmd
}

func CreateVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Prints the version of the relayers tool",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(RELAYERS_VERSION)
		},
	}
	return cmd
}

func CreateServeCommand() *cobra.Command {
	var relayerType, bindAddress string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a relayer server",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := RunServer(relayerType, bindAddress)
			return err
		},
	}

	cmd.Flags().StringVarP(&relayerType, "relayer", "r", "", "Type of relayer you would like to serve. Choices: \"erc721\".")
	cmd.Flags().StringVarP(&bindAddress, "bind", "b", "", "Address to bind the server to. For example, to bind to port 3743, you would use --bind \":3743\". Default: \":3743\".")

	return cmd
}

func CreateAuthorizationCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authorization",
		Short: "Create an authorization message for a given source asset",
	}

	var erc721HashOnly bool
	var erc721SourceChainID, erc721Recipient, erc721SourceContractAddress, erc721SourceTokenId, erc721DestinationAddress, erc721LiveUntil, erc721MetadataURI, erc721KeystoreFile string
	var erc721AuthorizeBefore int64
	erc721Cmd := &cobra.Command{
		Use:   "erc721",
		Short: "Create an authorization message for an ERC721 source contract",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO(zomglings): All arguments required except --hash. Do the checks here.

			chainID, parseOK := new(big.Int).SetString(erc721SourceChainID, 0)
			if !parseOK {
				return fmt.Errorf("could not parse chain ID:  %s", erc721SourceChainID)
			}
			request := &CreateMessageHashRequest{
				Recipient:     erc721Recipient,
				TokenID:       erc721SourceTokenId,
				SourceID:      erc721SourceContractAddress,
				SourceTokenID: erc721SourceTokenId,
				LiveUntil:     erc721LiveUntil,
				MetadataURI:   erc721MetadataURI,
			}

			var parameters RelayerFunctionParameters
			parseErr := parameters.ParseCreateMessageHashRequest(request)
			if parseErr != nil {
				return parseErr
			}

			if erc721HashOnly {
				messageHash, hashErr := ERC721AuthorizationPayloadHash(chainID, parameters.Recipient, parameters.TokenID, parameters.SourceID, parameters.SourceTokenID, parameters.LiveUntil, parameters.MetadataURI, erc721AuthorizeBefore)
				if hashErr != nil {
					return hashErr
				}
				cmd.Printf("Authorization message hash: %s\n", hex.EncodeToString(messageHash))
			} else {
				if erc721KeystoreFile == "" {
					return fmt.Errorf("you must specify a keystore file to sign the authorization message with")
				}

				signature, signErr := ERC721SignAuthorizationPayload(erc721KeystoreFile, chainID, parameters.Recipient, parameters.TokenID, parameters.SourceID, parameters.SourceTokenID, parameters.LiveUntil, parameters.MetadataURI, erc721AuthorizeBefore)
				if signErr != nil {
					return signErr
				}
				cmd.Printf("Signature: %s\n", hex.EncodeToString(signature))
			}

			return nil
		},
	}
	erc721Cmd.Flags().BoolVarP(&erc721HashOnly, "hash", "H", false, "Only output the hash of the authorization message, do not sign it.")
	erc721Cmd.Flags().StringVarP(&erc721KeystoreFile, "keystore", "k", "", "Path to the keystore file containing the private key to sign the authorization message with.")
	erc721Cmd.Flags().StringVarP(&erc721SourceChainID, "chain-id", "c", "", "Chain ID of the source chain. For example, for Ethereum mainnet, this would be \"1\".")
	erc721Cmd.Flags().StringVarP(&erc721Recipient, "recipient", "r", "", "Address which can mint the Ethereal NFT on the target Ethereal.")
	erc721Cmd.Flags().StringVarP(&erc721SourceContractAddress, "address", "a", "", "Address of the source contract. For example, for CryptoKitties, this would be \"0x06012c8cf97bead5deae237070f9587f8e7a266d\".")
	erc721Cmd.Flags().StringVarP(&erc721SourceTokenId, "token-id", "t", "", "Token ID of the source token.")
	erc721Cmd.Flags().StringVarP(&erc721DestinationAddress, "destination", "d", "", "Address of the target Ethereal contract.")
	erc721Cmd.Flags().StringVarP(&erc721MetadataURI, "metadata-uri", "u", "", "URI of the metadata for the Ethereal.")
	erc721Cmd.Flags().StringVarP(&erc721LiveUntil, "live-until", "l", "", "Unix timestamp until which the Ethereal is guaranteed to live.")
	erc721Cmd.Flags().Int64VarP(&erc721AuthorizeBefore, "authorize-before", "b", 0, "Unix timestamp before which the authorization is valid.")

	cmd.AddCommand(erc721Cmd)

	return cmd
}
