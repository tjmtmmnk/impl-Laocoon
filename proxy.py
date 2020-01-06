from typing import List, Tuple

from umbral.pre import Capsule

from config import NUM_OF_VOTER
from voter import Voter


class Proxy:
    _unique_instance = None

    def __new__(cls):
        raise NotImplementedError('Cannot initialize via Constructor')

    @classmethod
    def __internal_new__(cls):
        return super().__new__(cls)

    @classmethod
    def get_instance(cls):
        if not cls._unique_instance:
            cls.ciphertexts = []
            cls._unique_instance = cls.__internal_new__()

        return cls._unique_instance

    def receive_ciphertext_from_admin(self, ciphertext: Tuple[bytes, Capsule]):
        self.ciphertexts.append(ciphertext)

    def transfer_ciphertexts_to_voter(self, voters: List[Voter]):
        """transfer credential to voter

        Arguments:
            voters {List[Voter]}

        Raises:
            Exception: not match the num of voters
        """
        if len(self.ciphertexts) != NUM_OF_VOTER:
            raise Exception(
                "Not matched between num of voters and num of ciphertexts")
        shuffled_voters = voters.sample(voters, len(voters))

        for j, voter in enumerate(shuffled_voters):
            