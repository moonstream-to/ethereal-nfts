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
	"fmt"
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

	cmd.AddCommand(versionCmd, serveCmd)

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
	var bindAddress string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a relayer server",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := RunServer(bindAddress)
			return err
		},
	}

	cmd.Flags().StringVarP(&bindAddress, "bind", "b", "", "Address to bind the server to. For example, to bind to port 3743, you would use --bind \":3743\"")

	return cmd
}
