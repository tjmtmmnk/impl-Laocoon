from typing import Tuple

from umbral.pre import Capsule

from config import NUM_OF_VOTER


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

    def transfer_credential_to_voter(self):
        if len(self.ciphertexts) != NUM_OF_VOTER:
            raise Exception(
                "Not matched between num of voters and num of ciphertexts")
        transferred_voter_ids = []
