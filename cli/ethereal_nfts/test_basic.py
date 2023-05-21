from collections import defaultdict
import time
import unittest

from brownie import accounts, network, web3 as web3_client
from brownie.exceptions import VirtualMachineError
from brownie.network import chain
from eth_account._utils.signing import sign_message_hash
import eth_keys
from hexbytes import HexBytes
from moonworm.watch import _fetch_events_chunk

from . import BasicEthereal

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

MAX_UINT = 2**256 - 1


def sign_message(message_hash, signer):
    eth_private_key = eth_keys.keys.PrivateKey(HexBytes(signer.private_key))
    message_hash_bytes = HexBytes(message_hash)
    _, _, _, signed_message_bytes = sign_message_hash(
        eth_private_key, message_hash_bytes
    )
    return signed_message_bytes.hex()


class EtherealTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            network.connect()
        except:
            pass

        cls.ethereal = BasicEthereal.BasicEthereal(None)
        cls.signers = cls.deploy_ethereal(accounts[0])

    @classmethod
    def deploy_ethereal(cls, deployer):
        """
        Deploys an Ethereal contract and stores it under cls.ethereal.

        Returns a defaultdict mapping sourceIDs to a list of accounts that can sign for that sourceID.
        """
        cls.ethereal.deploy("Test", "TEST", {"from": deployer})
        signer = accounts.add()
        cls.ethereal.transfer_ownership(signer.address, {"from": deployer})
        return defaultdict(lambda: [signer])

    def test_supports_interface(self):
        # Supports IERC721
        self.assertTrue(self.ethereal.supports_interface("0x80ac58cd"))
        # Supports IERC721Metadata
        self.assertTrue(self.ethereal.supports_interface("0x5b5e139f"))
        # Supports IEthereal
        self.assertTrue(self.ethereal.supports_interface("0x6b583c91"))

    def test_create(self):
        """
        Tests that the intended recipient for an Ethereal NFT can claim their NFT as long as they make the
        claim before the liveness deadline and with a valid signature.
        """
        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 42
        source_id = 1
        source_token_id = 42
        # If this test doesn't complete in an hour... there are other serious problems.
        live_until = int(time.time()) + 3600
        metadata_uri = f"https://example.com/source_nfts/{token_id}.json"

        message_hash = self.ethereal.create_message_hash(
            recipient=recipient,
            token_id=token_id,
            source_id=source_id,
            source_token_id=source_token_id,
            live_until=live_until,
            metadata_uri=metadata_uri,
        )

        signer = self.signers[source_id][0]

        signature = sign_message(message_hash, signer)

        # If a token has not been minted, the `ownerOf` function on the OpenZeppelin ERC721 implementation
        # reverts.
        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(token_id)

        self.ethereal.create(
            recipient=recipient,
            token_id=token_id,
            source_id=source_id,
            source_token_id=source_token_id,
            live_until=live_until,
            metadata_uri=metadata_uri,
            signer=signer.address,
            signature=signature,
            transaction_config={"from": recipient_account},
        )

        token_owner_1 = self.ethereal.owner_of(token_id)
        self.assertEqual(token_owner_1, recipient)

        created_events = _fetch_events_chunk(
            web3=web3_client,
            event_abi=CREATED_EVENT_ABI,
            from_block=chain.height,
            to_block=chain.height,
            addresses=[self.ethereal.address],
        )
        self.assertEqual(len(created_events), 1)

        event = created_events[0]
        self.assertEqual(event["event"], "Created")
        self.assertEqual(event["args"]["recipient"], recipient)
        self.assertEqual(event["args"]["tokenId"], token_id)
        self.assertEqual(event["args"]["sourceId"], source_id)
        self.assertEqual(event["args"]["sourceTokenId"], source_token_id)
        self.assertEqual(event["args"]["liveUntil"], live_until)
        self.assertEqual(event["args"]["metadataURI"], metadata_uri)
        self.assertEqual(event["args"]["signer"], signer.address)

    def test_create_delegated(self):
        """
        Tests that a delegate can claim an Ethereal NFT *to* the intended recipient as long as they
        make the claim before the liveness deadline and with a valid signature.
        """
        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 43
        source_id = 1
        source_token_id = 42
        # If this test doesn't complete in an hour... there are other serious problems.
        live_until = int(time.time()) + 3600
        metadata_uri = f"https://example.com/source_nfts/{token_id}.json"

        message_hash = self.ethereal.create_message_hash(
            recipient=recipient,
            token_id=token_id,
            source_id=source_id,
            source_token_id=source_token_id,
            live_until=live_until,
            metadata_uri=metadata_uri,
        )

        signer = self.signers[source_id][0]

        signature = sign_message(message_hash, signer)

        # If a token has not been minted, the `ownerOf` function on the OpenZeppelin ERC721 implementation
        # reverts.
        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(token_id)

        # This is the key difference from test_create. Transaction is being submitted by a different account
        # than the intended recipient.
        self.ethereal.create(
            recipient=recipient,
            token_id=token_id,
            source_id=source_id,
            source_token_id=source_token_id,
            live_until=live_until,
            metadata_uri=metadata_uri,
            signer=signer.address,
            signature=signature,
            transaction_config={"from": accounts[0]},
        )

        token_owner_1 = self.ethereal.owner_of(token_id)
        self.assertEqual(token_owner_1, recipient)

        created_events = _fetch_events_chunk(
            web3=web3_client,
            event_abi=CREATED_EVENT_ABI,
            from_block=chain.height,
            to_block=chain.height,
            addresses=[self.ethereal.address],
        )
        self.assertEqual(len(created_events), 1)

        event = created_events[0]
        self.assertEqual(event["event"], "Created")
        self.assertEqual(event["args"]["recipient"], recipient)
        self.assertEqual(event["args"]["tokenId"], token_id)
        self.assertEqual(event["args"]["sourceId"], source_id)
        self.assertEqual(event["args"]["sourceTokenId"], source_token_id)
        self.assertEqual(event["args"]["liveUntil"], live_until)
        self.assertEqual(event["args"]["metadataURI"], metadata_uri)
        self.assertEqual(event["args"]["signer"], signer.address)


if __name__ == "__main__":
    unittest.main()

# Event ABIs

CREATED_EVENT_ABI = {
    "anonymous": False,
    "inputs": [
        {
            "indexed": True,
            "internalType": "address",
            "name": "recipient",
            "type": "address",
        },
        {
            "indexed": True,
            "internalType": "uint256",
            "name": "tokenId",
            "type": "uint256",
        },
        {
            "indexed": False,
            "internalType": "uint256",
            "name": "sourceId",
            "type": "uint256",
        },
        {
            "indexed": False,
            "internalType": "uint256",
            "name": "sourceTokenId",
            "type": "uint256",
        },
        {
            "indexed": False,
            "internalType": "uint256",
            "name": "liveUntil",
            "type": "uint256",
        },
        {
            "indexed": False,
            "internalType": "string",
            "name": "metadataURI",
            "type": "string",
        },
        {
            "indexed": True,
            "internalType": "address",
            "name": "signer",
            "type": "address",
        },
    ],
    "name": "Created",
    "type": "event",
}
