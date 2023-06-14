#!/usr/bin/env sh

# Run code generation routines.
# This generates:
# - cli/ethereal_nfts/BasicEthereal.py
# - contracts/IEthereal.sol
#
# Requires:
# - brownie (https://github.com/eth-brownie/brownie)
# - jq (https://jqlang.github.io/jq/)
# - moonworm (https://github.com/moonstream-to/moonworm)
# - solface (https://github.com/moonstream-to/solface)

set -e

SCRIPT_DIR="$(dirname $(realpath $0))"


cd $SCRIPT_DIR

brownie compile

cat >contracts/IEthereal.sol <<EOS
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

EOS
jq .abi build/contracts/Ethereal.json | solface -name IEthereal -annotations >>contracts/IEthereal.sol

brownie compile

moonworm generate-brownie -p . -o cli/ethereal_nfts/ -n BasicEthereal
moonworm generate-brownie -p . -o cli/ethereal_nfts/ -n EtherealDeployer
