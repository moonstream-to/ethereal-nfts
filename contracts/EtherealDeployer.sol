// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import {BasicEthereal} from "./Ethereal.sol";

// EtherealDeployer is a contract that deploys Ethereal NFT contracts using CREATE2.
// CREATE2: https://eips.ethereum.org/EIPS/eip-1014
// More details: https://ethereum.stackexchange.com/questions/101336/what-is-the-benefit-of-using-create2-to-create-a-smart-contract
contract EtherealDeployer {
    event EtherealDeployed(address etherealContractAddress);

    // Modeled off of computeAddress from OpenZeppelin's Create2 contract: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/d6c7cee32191850d3635222826985f46996e64fd/contracts/utils/Create2.sol
    function calculateAddress(
        bytes32 salt,
        bytes memory bytecode
    ) internal view returns (address result) {
        address deployer = address(this);
        bytes32 bytecodeHash = keccak256(bytecode);

        assembly {
            let ptr := mload(0x40) // Get free memory pointer

            // |                   | ↓ ptr ...  ↓ ptr + 0x0B (start) ...  ↓ ptr + 0x20 ...  ↓ ptr + 0x40 ...   |
            // |-------------------|---------------------------------------------------------------------------|
            // | bytecodeHash      |                                                        CCCCCCCCCCCCC...CC |
            // | salt              |                                      BBBBBBBBBBBBB...BB                   |
            // | deployer          | 000000...0000AAAAAAAAAAAAAAAAAAA...AA                                     |
            // | 0xFF              |            FF                                                             |
            // |-------------------|---------------------------------------------------------------------------|
            // | memory            | 000000...00FFAAAAAAAAAAAAAAAAAAA...AABBBBBBBBBBBBB...BBCCCCCCCCCCCCC...CC |
            // | keccak(start, 85) |            ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑ |

            mstore(add(ptr, 0x40), bytecodeHash)
            mstore(add(ptr, 0x20), salt)
            mstore(ptr, deployer) // Right-aligned with 12 preceding garbage bytes
            let start := add(ptr, 0x0b) // The hashed data starts at the final garbage byte which we will set to 0xff
            mstore8(start, 0xff)
            result := keccak256(start, 85)
        }
    }

    function BasicEtherealSalt(
        string memory name_arg,
        string memory symbol_arg
    ) public pure returns (bytes32 result) {
        return keccak256(abi.encodePacked(name_arg, symbol_arg));
    }

    function BasicEtherealAddress(
        string memory name_arg,
        string memory symbol_arg
    ) external view returns (address result) {
        bytes32 salt = BasicEtherealSalt(name_arg, symbol_arg);
        // OMG init code: https://ethereum.stackexchange.com/questions/76334/what-is-the-difference-between-bytecode-init-code-deployed-bytecode-creation
        bytes memory bytecode = type(BasicEthereal).creationCode;
        bytes memory initCode = abi.encodePacked(
            bytecode,
            abi.encode(name_arg, symbol_arg)
        );
        return calculateAddress(salt, initCode);
    }

    // Deploys a new BasicEthereal contract which uses the OpenZeppelin Ownership contract to signify relayer authority.
    // Calculates salt from name and symbol.
    function DeployBasicEthereal(
        string memory name_arg,
        string memory symbol_arg,
        address owner
    ) external returns (address result) {
        bytes32 salt = BasicEtherealSalt(name_arg, symbol_arg);
        BasicEthereal deployedContract = new BasicEthereal{salt: salt}(
            name_arg,
            symbol_arg
        );
        deployedContract.transferOwnership(owner);
        result = address(deployedContract);
        emit EtherealDeployed(result);
    }
}
