import unittest

from brownie import accounts, network, web3 as web3_client
from brownie.exceptions import VirtualMachineError
from brownie.network import chain
from eth_account._utils.signing import sign_message_hash
import eth_keys
from hexbytes import HexBytes
from moonworm.watch import _fetch_events_chunk

from . import BasicEthereal, EtherealDeployer

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

MAX_UINT = 2**256 - 1


class EtherealDeployerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            network.connect()
        except:
            pass

        cls.ethereal_deployer = EtherealDeployer.EtherealDeployer(None)
        cls.ethereal_deployer.deploy({"from": accounts[0]})

    def test_deploy_basic_ethereal(self):
        name = "Laugh out loud NFTs"
        symbol = "LOL"

        self.ethereal_deployer.deploy_basic_ethereal(
            name, symbol, accounts[2].address, {"from": accounts[1]}
        )

        deployment_events = _fetch_events_chunk(
            web3=web3_client,
            event_abi=ETHEREAL_DEPLOYED_ABI,
            from_block=chain.height,
            to_block=chain.height,
            addresses=[self.ethereal_deployer.address],
        )

        self.assertEqual(len(deployment_events), 1)

        deployment_address = deployment_events[0]["args"]["etherealContractAddress"]

        self.assertEqual(
            deployment_address,
            self.ethereal_deployer.get_basic_ethereal_address(name, symbol),
        )

        basic_ethereal = BasicEthereal.BasicEthereal(deployment_address)
        self.assertEqual(basic_ethereal.name(), name)
        self.assertEqual(basic_ethereal.symbol(), symbol)
        self.assertEqual(basic_ethereal.owner(), accounts[2].address)


# ABIs

ETHEREAL_DEPLOYED_ABI = {
    "anonymous": False,
    "inputs": [
        {
            "indexed": False,
            "internalType": "address",
            "name": "etherealContractAddress",
            "type": "address",
        }
    ],
    "name": "EtherealDeployed",
    "type": "event",
}


if __name__ == "__main__":
    unittest.main()
