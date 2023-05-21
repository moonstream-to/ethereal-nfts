from collections import defaultdict
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


if __name__ == "__main__":
    unittest.main()
