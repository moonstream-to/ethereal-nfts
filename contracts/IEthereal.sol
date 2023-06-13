// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;


// Interface generated by solface: https://github.com/moonstream-to/solface
// solface version: 0.1.0
// Interface ID: 8737034c
interface IEthereal {
	// structs

	// events
	event Approval(address owner, address approved, uint256 tokenId);
	event ApprovalForAll(address owner, address operator, bool approved);
	event Created(address recipient, uint256 tokenId, uint256 sourceId, uint256 sourceTokenId, uint256 liveUntil, string metadataURI, address signer);
	event Destroyed(uint256 tokenId, address destroyer);
	event Transfer(address from, address to, uint256 tokenId);

	// functions
	// Selector: d5561840
	function CurrentEtherealTokenID(uint256 , uint256 ) external view returns (uint256);
	// Selector: cdd46ad2
	function LiveUntil(uint256 ) external view returns (uint256);
	// Selector: 67dbbe43
	function MetadataURI(uint256 ) external view returns (string memory);
	// Selector: 8dd72e4a
	function Source(uint256 ) external view returns (uint256);
	// Selector: dcfd1470
	function SourceTokenID(uint256 ) external view returns (uint256);
	// Selector: 095ea7b3
	function approve(address to, uint256 tokenId) external ;
	// Selector: 70a08231
	function balanceOf(address owner) external view returns (uint256);
	// Selector: f9152508
	function create(address recipient, uint256 tokenId, uint256 sourceId, uint256 sourceTokenId, uint256 liveUntil, string memory metadataURI, address signer, bytes memory signature) external ;
	// Selector: bb216ee6
	function createMessageHash(address recipient, uint256 tokenId, uint256 sourceId, uint256 sourceTokenId, uint256 liveUntil, string memory metadataURI) external view returns (bytes32);
	// Selector: 9d118770
	function destroy(uint256 tokenId) external ;
	// Selector: 081812fc
	function getApproved(uint256 tokenId) external view returns (address);
	// Selector: e985e9c5
	function isApprovedForAll(address owner, address operator) external view returns (bool);
	// Selector: ac6cbbcc
	function isSignerValidForSource(address signer, uint256 sourceId) external view returns (bool);
	// Selector: 06fdde03
	function name() external view returns (string memory);
	// Selector: 6352211e
	function ownerOf(uint256 tokenId) external view returns (address);
	// Selector: 42842e0e
	function safeTransferFrom(address from, address to, uint256 tokenId) external ;
	// Selector: b88d4fde
	function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) external ;
	// Selector: a22cb465
	function setApprovalForAll(address operator, bool approved) external ;
	// Selector: 01ffc9a7
	function supportsInterface(bytes4 interfaceId) external view returns (bool);
	// Selector: 95d89b41
	function symbol() external view returns (string memory);
	// Selector: c87b56dd
	function tokenURI(uint256 tokenId) external view returns (string memory);
	// Selector: 23b872dd
	function transferFrom(address from, address to, uint256 tokenId) external ;

	// errors
	error InvalidSignature(address recipient, uint256 tokenId, uint256 sourceId, uint256 sourceTokenId, uint256 liveUntil, string metadataURI, address signer, bytes32 messageHash, bytes signature);
	error InvalidSignerForSource(address signer, uint256 sourceId);
	error InvalidTokenID(uint256 tokenId);
	error LivenessDeadlineExpired(uint256 liveUntil);
	error TokenAlreadyIssued(uint256 sourceId, uint256 sourceTokenId, uint256 existingTokenId);
	error TokenDoesNotExist(uint256 tokenId);
	error TokenNotExpired(uint256 tokenId, uint256 liveUntil);
}
