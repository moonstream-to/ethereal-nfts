// SPDX-License-Identifier: Apache-2.0

/**
 * Authors: Moonstream Engineering (engineering@moonstream.to)
 * GitHub: https://github.com/great-wyrm/contracts
 */
pragma solidity ^0.8.0;

import {ERC721} from "@openzeppelin/contracts/contracts/token/ERC721/ERC721.sol";
import {EIP712} from "@openzeppelin/contracts/contracts/utils/cryptography/EIP712.sol";
import {IERC1271} from "@openzeppelin/contracts/contracts/interfaces/IERC1271.sol";
import {SignatureChecker} from "@openzeppelin/contracts/contracts/utils/cryptography/SignatureChecker.sol";
import {Ownable} from "@openzeppelin/contracts/contracts/access/Ownable.sol";
import {IEthereal} from "./IEthereal.sol";

abstract contract Ethereal is ERC721, EIP712 {
    // tokenId of Ethereal NFT => source that the NFT corresponds to
    // This source can be any positive integer. The special value 0 corresponds to the null source.
    // An Ethereal NFT for which the source is 0 is considered to be inactive and unusable.
    // Sources are meant to represent the original sources of truth for the Ethereal NFTs that are issued
    // on this contract. They can be:
    // 1. ERC721 contracts on the same chain as the Ethereal NFT.
    // 2. ERC721 contract on other Ethereum-compatible blockchains (e.g. Polygon, BSC, etc.).
    // 3. NFT programs on blockchains which are not Ethereum-compatible - the only restriction we place
    // is that the tokens issued by those programs can be mapped into 256 bits. See SourceTokenID.
    // 4. Game servers which issue digital assets (such as characters, unique items, etc.) which can be
    // mapped to NFTs.
    mapping(uint256 => uint256) public Source;
    // tokenId of Ethereal NFT => source identifier for the token the Ethereal NFT derives from
    mapping(uint256 => uint256) public SourceTokenID;
    // Maps (source, source token ID) => Ethereal token ID
    // This mapping is used to guarantee that multiple Ethereal NFTs are not issued for each (source, source token) pair.
    mapping(uint256 => mapping(uint256 => uint256))
        public CurrentEtherealTokenID;
    // tokenId of Ethereal NFT => block timestamp until the NFT can be publicly destroyed
    // An Ethereal NFT can only be destroyed *strictly after* this timestamp.
    mapping(uint256 => uint256) public LiveUntil;
    // tokenId of Ethereal NFT => metadata URI of Ethereal NFT
    mapping(uint256 => string) public MetadataURI;

    event Created(
        address indexed recipient,
        uint256 indexed tokenId,
        uint256 sourceId,
        uint256 sourceTokenId,
        uint256 liveUntil,
        string metadataURI,
        address indexed signer
    );
    event Destroyed(uint256 indexed tokenId, address indexed destroyer);

    error InvalidCreateSignature(
        address recipient,
        uint256 tokenId,
        uint256 sourceId,
        uint256 sourceTokenId,
        uint256 liveUntil,
        string metadataURI,
        address signer,
        bytes32 messageHash,
        bytes signature
    );
    error InvalidBurnSignature(
        uint256 tokenId,
        address signer,
        bytes32 messageHash,
        bytes signature
    );
    error LivenessDeadlineExpired(uint256 liveUntil);
    error InvalidSignerForSource(address signer, uint256 sourceId);
    error TokenNotExpired(uint256 tokenId, uint256 liveUntil);
    error TokenDoesNotExist(uint256 tokenId);
    error TokenAlreadyIssued(
        uint256 sourceId,
        uint256 sourceTokenId,
        uint256 existingTokenId
    );
    error InvalidTokenID(uint256 tokenId);

    function isSignerValidForSource(
        address signer,
        uint256 sourceId
    ) public view virtual returns (bool);

    constructor(
        string memory name_arg,
        string memory symbol_arg
    ) ERC721(name_arg, symbol_arg) EIP712("ethereal", "0.0.1") {}

    function supportsInterface(
        bytes4 interfaceId
    ) public view override returns (bool) {
        return
            interfaceId == type(IEthereal).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function tokenURI(
        uint256 tokenId
    ) public view override returns (string memory) {
        return MetadataURI[tokenId];
    }

    function createMessageHash(
        address recipient,
        uint256 tokenId,
        uint256 sourceId,
        uint256 sourceTokenId,
        uint256 liveUntil,
        string memory metadataURI
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "CreatePayload(address recipient,uint256 tokenId,uint256 sourceId,uint256 sourceTokenId,uint256 liveUntil,string metadataURI)"
                ),
                recipient,
                tokenId,
                sourceId,
                sourceTokenId,
                liveUntil,
                keccak256(bytes(metadataURI))
            )
        );
        return _hashTypedDataV4(structHash);
    }

    function burnMessageHash(uint256 tokenId) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(keccak256("BurnPayload(uint256 tokenId)"), tokenId)
        );
        return _hashTypedDataV4(structHash);
    }

    function create(
        address recipient,
        uint256 tokenId,
        uint256 sourceId,
        uint256 sourceTokenId,
        uint256 liveUntil,
        string memory metadataURI,
        address signer,
        bytes memory signature
    ) external {
        if (tokenId == 0) {
            revert InvalidTokenID(tokenId);
        }

        bytes32 messageHash = createMessageHash(
            recipient,
            tokenId,
            sourceId,
            sourceTokenId,
            liveUntil,
            metadataURI
        );
        bool signatureIsValid = SignatureChecker.isValidSignatureNow(
            signer,
            messageHash,
            signature
        );
        if (!signatureIsValid) {
            revert InvalidCreateSignature(
                recipient,
                tokenId,
                sourceId,
                sourceTokenId,
                liveUntil,
                metadataURI,
                signer,
                messageHash,
                signature
            );
        }
        if (!isSignerValidForSource(signer, sourceId)) {
            revert InvalidSignerForSource(signer, sourceId);
        }

        if (Source[tokenId] != 0) {
            if (block.timestamp <= LiveUntil[tokenId]) {
                revert TokenNotExpired(tokenId, LiveUntil[tokenId]);
            } else {
                // This sets the Source and SourceTokenID to 0, marking the Ethereal token ID as inactive.
                destroy(tokenId);
            }
        }

        if (CurrentEtherealTokenID[sourceId][sourceTokenId] != 0) {
            revert TokenAlreadyIssued(
                sourceId,
                sourceTokenId,
                CurrentEtherealTokenID[sourceId][sourceTokenId]
            );
        }

        if (block.timestamp > liveUntil) {
            revert LivenessDeadlineExpired(liveUntil);
        }

        Source[tokenId] = sourceId;
        SourceTokenID[tokenId] = sourceTokenId;
        CurrentEtherealTokenID[sourceId][sourceTokenId] = tokenId;
        LiveUntil[tokenId] = liveUntil;
        MetadataURI[tokenId] = metadataURI;
        _mint(recipient, tokenId);

        emit Created(
            recipient,
            tokenId,
            sourceId,
            sourceTokenId,
            liveUntil,
            metadataURI,
            signer
        );
    }

    function burn(
        uint256 tokenId,
        address signer,
        bytes memory signature
    ) external {
        if (tokenId == 0) {
            revert InvalidTokenID(tokenId);
        }
        bytes32 messageHash = burnMessageHash(tokenId);
        bool signatureIsValid = SignatureChecker.isValidSignatureNow(
            signer,
            messageHash,
            signature
        );
        if (!signatureIsValid) {
            revert InvalidBurnSignature(
                tokenId,
                signer,
                messageHash,
                signature
            );
        }
        uint256 sourceId = Source[tokenId];
        if (!isSignerValidForSource(signer, sourceId)) {
            revert InvalidSignerForSource(signer, sourceId);
        }
        _burn(tokenId);
    }

    function destroy(uint256 tokenId) public {
        if (Source[tokenId] == 0) {
            revert TokenDoesNotExist(tokenId);
        }
        if (block.timestamp <= LiveUntil[tokenId]) {
            revert TokenNotExpired(tokenId, LiveUntil[tokenId]);
        }
        _burn(tokenId);
    }

    function _burn(uint256 tokenId) internal override {
        super._burn(tokenId);

        MetadataURI[tokenId] = "";
        LiveUntil[tokenId] = 0;
        CurrentEtherealTokenID[Source[tokenId]][SourceTokenID[tokenId]] = 0;
        SourceTokenID[tokenId] = 0;
        Source[tokenId] = 0;

        emit Destroyed(tokenId, msg.sender);
    }
}

contract BasicEthereal is Ethereal, Ownable {
    constructor(
        string memory name_arg,
        string memory symbol_arg
    ) Ethereal(name_arg, symbol_arg) {}

    function isSignerValidForSource(
        address signer,
        uint256 sourceId
    ) public view override returns (bool) {
        return signer == owner();
    }
}
