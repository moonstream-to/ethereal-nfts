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
        """
        Test that Ethereal NFT implementation supporst the correct interfaces according to EIP165.
        """
        # Supports IERC721
        self.assertTrue(self.ethereal.supports_interface("0x80ac58cd"))
        # Supports IERC721Metadata
        self.assertTrue(self.ethereal.supports_interface("0x5b5e139f"))
        # Supports IEthereal
        self.assertTrue(self.ethereal.supports_interface("0x8737034c"))

    def test_create(self):
        """
        Tests that the intended recipient for an Ethereal NFT can claim their NFT as long as they make the
        claim before the liveness deadline and with a valid signature.
        """
        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 42
        source_id = 1
        source_token_id = token_id
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
        self.assertEqual(self.ethereal.source(token_id), source_id)
        self.assertEqual(self.ethereal.source_token_id(token_id), source_token_id)
        self.assertEqual(self.ethereal.live_until(token_id), live_until)
        self.assertEqual(self.ethereal.token_uri(token_id), metadata_uri)

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
        source_token_id = token_id
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
        self.assertEqual(self.ethereal.source(token_id), source_id)
        self.assertEqual(self.ethereal.source_token_id(token_id), source_token_id)
        self.assertEqual(self.ethereal.live_until(token_id), live_until)
        self.assertEqual(self.ethereal.token_uri(token_id), metadata_uri)

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

    def test_create_fails_with_invalid_signer(self):
        """
        Tests that an Ethereal NFT cannot be created if the signer of the creation payload is not an
        authorized signer.

        Assumes that, if a new signer account is created, it will not be authorized!
        """
        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 44
        source_id = 1
        source_token_id = token_id
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

        invalid_signer = accounts.add()

        signature = sign_message(message_hash, invalid_signer)

        # If a token has not been minted, the `ownerOf` function on the OpenZeppelin ERC721 implementation
        # reverts.
        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(token_id)

        with self.assertRaises(VirtualMachineError):
            self.ethereal.create(
                recipient=recipient,
                token_id=token_id,
                source_id=source_id,
                source_token_id=source_token_id,
                live_until=live_until,
                metadata_uri=metadata_uri,
                signer=invalid_signer.address,
                signature=signature,
                transaction_config={"from": recipient_account},
            )

        # If a token has not been minted, the `ownerOf` function on the OpenZeppelin ERC721 implementation
        # reverts.
        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(token_id)

    def test_create_fails_with_invalid_signature(self):
        """
        Tests that an Ethereal NFT cannot be created if the signature does not match the creation payload
        and signer.

        Assumes that, if a new signer account is created, it will not be authorized!
        """
        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 45
        source_id = 1
        source_token_id = token_id
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
        invalid_signer = accounts.add()

        signature = sign_message(message_hash, invalid_signer)

        # If a token has not been minted, the `ownerOf` function on the OpenZeppelin ERC721 implementation
        # reverts.
        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(token_id)

        with self.assertRaises(VirtualMachineError):
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

        # If a token has not been minted, the `ownerOf` function on the OpenZeppelin ERC721 implementation
        # reverts.
        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(token_id)

    def test_create_fails_after_liveness_deadline(self):
        """
        Tests that an Ethereal NFT cannot be created after its liveness deadline has passed.
        """
        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 46
        source_id = 1
        source_token_id = token_id
        live_until = int(time.time()) - 1
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

        with self.assertRaises(VirtualMachineError):
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

        # If a token has not been minted, the `ownerOf` function on the OpenZeppelin ERC721 implementation
        # reverts.
        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(token_id)

    def test_ethereal_nft_cannot_be_created_if_it_is_still_live(self):
        """
        Tests that an Ethereal NFT that is still live cannot be recreated with the same recipient.
        """
        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 47
        source_id = 1
        source_token_id = token_id
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

        with self.assertRaises(VirtualMachineError):
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

        self.assertEqual(self.ethereal.live_until(token_id), live_until)

    def test_ethereal_nft_cannot_be_created_for_other_recipient_if_it_is_still_live(
        self,
    ):
        """
        Tests that an Ethereal NFT that is still live cannot be recreated with a different recipient.
        """
        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 48
        source_id = 1
        source_token_id = token_id
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

        other_recipient_account = accounts[2]
        other_recipient = other_recipient_account.address

        new_live_until = live_until + 3600

        message_hash_1 = self.ethereal.create_message_hash(
            recipient=other_recipient,
            token_id=token_id,
            source_id=source_id,
            source_token_id=source_token_id,
            live_until=new_live_until,
            metadata_uri=metadata_uri,
        )

        signer = self.signers[source_id][0]

        signature = sign_message(message_hash_1, signer)

        with self.assertRaises(VirtualMachineError):
            self.ethereal.create(
                recipient=other_recipient,
                token_id=token_id,
                source_id=source_id,
                source_token_id=source_token_id,
                live_until=new_live_until,
                metadata_uri=metadata_uri,
                signer=signer.address,
                signature=signature,
                transaction_config={"from": other_recipient_account},
            )

        token_owner_2 = self.ethereal.owner_of(token_id)

        self.assertEqual(token_owner_2, recipient)
        self.assertEqual(self.ethereal.live_until(token_id), live_until)

    def test_ethereal_nft_can_be_created_for_other_recipient_after_liveness_deadline_expires(
        self,
    ):
        """
        Tests that an Ethereal NFT that is no longer live can be recreated with a different recipient.
        """
        liveness_interval = 2

        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 49
        source_id = 1
        source_token_id = token_id
        live_until = int(time.time()) + liveness_interval
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

        # When we only left 100 milliseconds in the sleep, we were getting an error because it seems
        # like the backing (ganache) blockchain had not registered the ownership change.
        # Even the current delay may be too short. This makes success non-deterministic.
        time.sleep(liveness_interval + 1)

        other_recipient_account = accounts[2]
        other_recipient = other_recipient_account.address
        new_live_until = live_until + 3600

        message_hash_1 = self.ethereal.create_message_hash(
            recipient=other_recipient,
            token_id=token_id,
            source_id=source_id,
            source_token_id=source_token_id,
            live_until=new_live_until,
            metadata_uri=metadata_uri,
        )

        signer = self.signers[source_id][0]

        signature = sign_message(message_hash_1, signer)

        self.ethereal.create(
            recipient=other_recipient,
            token_id=token_id,
            source_id=source_id,
            source_token_id=source_token_id,
            live_until=new_live_until,
            metadata_uri=metadata_uri,
            signer=signer.address,
            signature=signature,
            transaction_config={"from": other_recipient_account},
        )

        token_owner_2 = self.ethereal.owner_of(token_id)
        self.assertEqual(token_owner_2, other_recipient)
        self.assertEqual(self.ethereal.live_until(token_id), new_live_until)

    def test_ethereal_nft_cannot_be_created_with_the_same_source_data_as_another(
        self,
    ):
        """
        Tests that an Ethereal NFT cannot be created with duplicate source and sourceId
        """
        liveness_interval = 3600

        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 50
        source_id = 1
        source_token_id = token_id
        live_until = int(time.time()) + liveness_interval
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

        # First NFT is good for an hour, so second creation should fail.
        new_token_id = 51

        message_hash_1 = self.ethereal.create_message_hash(
            recipient=recipient,
            token_id=new_token_id,
            source_id=source_id,
            source_token_id=source_token_id,
            live_until=live_until,
            metadata_uri=metadata_uri,
        )

        signer = self.signers[source_id][0]

        signature = sign_message(message_hash_1, signer)

        with self.assertRaises(VirtualMachineError):
            self.ethereal.create(
                recipient=recipient,
                token_id=new_token_id,
                source_id=source_id,
                source_token_id=source_token_id,
                live_until=live_until,
                metadata_uri=metadata_uri,
                signer=signer.address,
                signature=signature,
                transaction_config={"from": recipient},
            )

        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(new_token_id)

    def test_ethereal_nft_can_be_created_with_duplicate_sourceid_if_the_source_is_different(
        self,
    ):
        """
        Tests that an Ethereal NFT cannot be created with duplicate source and sourceId
        """
        liveness_interval = 3600

        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 52
        source_id = 1
        source_token_id = token_id
        live_until = int(time.time()) + liveness_interval
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

        token_owner_0 = self.ethereal.owner_of(token_id)
        self.assertEqual(token_owner_0, recipient)

        token_id_1 = 53
        source_id_1 = 2
        metadata_uri_1 = f"https://example.com/source_nfts/{token_id_1}.json"

        message_hash_1 = self.ethereal.create_message_hash(
            recipient=recipient,
            token_id=token_id_1,
            source_id=source_id_1,
            # Duplicate source token id
            source_token_id=source_token_id,
            live_until=live_until,
            metadata_uri=metadata_uri_1,
        )

        signer_1 = self.signers[source_id_1][0]

        signature_1 = sign_message(message_hash_1, signer_1)

        self.ethereal.create(
            recipient=recipient,
            token_id=token_id_1,
            source_id=source_id_1,
            source_token_id=source_token_id,
            live_until=live_until,
            metadata_uri=metadata_uri_1,
            signer=signer_1.address,
            signature=signature_1,
            transaction_config={"from": recipient},
        )

        token_owner_1 = self.ethereal.owner_of(token_id)
        self.assertEqual(token_owner_1, recipient)

    def test_ethereal_nft_token_id_can_be_recycled(
        self,
    ):
        """
        Tests that an Ethereal NFT recycled with completely different data i.e. remnants of the old token are not left behind.
        """
        token_id = 54
        liveness_interval_0 = 2

        recipient_account_0 = accounts[1]
        recipient_0 = recipient_account_0.address
        source_id_0 = 1
        source_token_id_0 = 101
        live_until_0 = int(time.time()) + liveness_interval_0
        metadata_uri_0 = f"https://example.com/source_nfts/{token_id}_0.json"

        message_hash_0 = self.ethereal.create_message_hash(
            recipient=recipient_0,
            token_id=token_id,
            source_id=source_id_0,
            source_token_id=source_token_id_0,
            live_until=live_until_0,
            metadata_uri=metadata_uri_0,
        )

        signer_0 = self.signers[source_id_0][0]

        signature_0 = sign_message(message_hash_0, signer_0)

        # If a token has not been minted, the `ownerOf` function on the OpenZeppelin ERC721 implementation
        # reverts.
        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(token_id)

        self.ethereal.create(
            recipient=recipient_0,
            token_id=token_id,
            source_id=source_id_0,
            source_token_id=source_token_id_0,
            live_until=live_until_0,
            metadata_uri=metadata_uri_0,
            signer=signer_0.address,
            signature=signature_0,
            transaction_config={"from": recipient_account_0},
        )

        token_owner_0 = self.ethereal.owner_of(token_id)
        self.assertEqual(token_owner_0, recipient_0)
        self.assertEqual(self.ethereal.source(token_id), source_id_0)
        self.assertEqual(self.ethereal.source_token_id(token_id), source_token_id_0)
        self.assertEqual(self.ethereal.live_until(token_id), live_until_0)
        self.assertEqual(self.ethereal.token_uri(token_id), metadata_uri_0)

        # When we only left 100 milliseconds in the sleep, we were getting an error because it seems
        # like the backing (ganache) blockchain had not registered the ownership change.
        # Even the current delay may be too short. This makes success non-deterministic.
        time.sleep(liveness_interval_0 + 1)

        recipient_account_1 = accounts[2]
        recipient_1 = recipient_account_1.address
        source_id_1 = 2
        source_token_id_1 = 102
        metadata_uri_1 = f"https://example.com/source_nfts/{token_id}_1.json"
        liveness_interval_1 = 4
        live_until_1 = int(time.time()) + liveness_interval_1

        message_hash_1 = self.ethereal.create_message_hash(
            recipient=recipient_1,
            # Same token id
            token_id=token_id,
            source_id=source_id_1,
            source_token_id=source_token_id_1,
            live_until=live_until_1,
            metadata_uri=metadata_uri_1,
        )

        signer_1 = self.signers[source_id_1][0]

        signature_1 = sign_message(message_hash_1, signer_1)

        self.ethereal.create(
            recipient=recipient_1,
            token_id=token_id,
            source_id=source_id_1,
            source_token_id=source_token_id_1,
            live_until=live_until_1,
            metadata_uri=metadata_uri_1,
            signer=signer_1.address,
            signature=signature_1,
            transaction_config={"from": recipient_1},
        )

        token_owner_1 = self.ethereal.owner_of(token_id)
        self.assertEqual(token_owner_1, recipient_1)
        self.assertEqual(self.ethereal.source(token_id), source_id_1)
        self.assertEqual(self.ethereal.source_token_id(token_id), source_token_id_1)
        self.assertEqual(self.ethereal.live_until(token_id), live_until_1)
        self.assertEqual(self.ethereal.token_uri(token_id), metadata_uri_1)

    def test_ethereal_nft_can_be_destroyed_after_live_until(
        self,
    ):
        """
        Tests that an Ethereal NFT can be destroyed after live until timestamp has passed.
        """
        liveness_interval = 2

        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 55
        source_id = 1
        source_token_id = token_id
        live_until = int(time.time()) + liveness_interval
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

        # When we only left 100 milliseconds in the sleep, we were getting an error because it seems
        # like the backing (ganache) blockchain had not registered the ownership change.
        # Even the current delay may be too short. This makes success non-deterministic.
        time.sleep(liveness_interval + 1)

        self.ethereal.destroy(token_id, transaction_config={"from": recipient_account})

        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(token_id)

    def test_ethereal_nft_can_be_destroyed_by_anyone(
        self,
    ):
        """
        Tests that an Ethereal NFT can be destroyed by anyone (after live until timestamp has passed).
        """
        liveness_interval = 2

        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 56
        source_id = 1
        source_token_id = token_id
        live_until = int(time.time()) + liveness_interval
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

        # When we only left 100 milliseconds in the sleep, we were getting an error because it seems
        # like the backing (ganache) blockchain had not registered the ownership change.
        # Even the current delay may be too short. This makes success non-deterministic.
        time.sleep(liveness_interval + 1)

        self.ethereal.destroy(token_id, transaction_config={"from": accounts[2]})

        with self.assertRaises(VirtualMachineError):
            self.ethereal.owner_of(token_id)

    def test_ethereal_nft_cannot_be_destroyed_before_live_until(
        self,
    ):
        """
        Tests that an Ethereal NFT cannot be destroyed before live until timestamp has passed.
        """
        liveness_interval = 3600

        recipient_account = accounts[1]
        recipient = recipient_account.address
        token_id = 57
        source_id = 1
        source_token_id = token_id
        live_until = int(time.time()) + liveness_interval
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

        # Removed sleep from the sucessful destroy test.

        with self.assertRaises(VirtualMachineError):
            self.ethereal.destroy(
                token_id, transaction_config={"from": recipient_account}
            )


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
