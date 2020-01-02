import random
from umbral import pre, keys, config, signing
from bulletinboard import BulletinBoard

NUM_OF_VOTER = 5
NUM_OF_CANDIDATE = 3

class Administrator:
    def __init__(self):
        config.set_default_curve()
        self.bb = BulletinBoard.get_instance()
        self.private_key = keys.UmbralPrivateKey.gen_key()
        self.public_key = self.private_key.get_pubkey()
        self.singning_key = keys.UmbralPrivateKey.gen_key()
        self.verifying_key = self.singning_key.get_pubkey()

    @classmethod
    def setup(self):
        self._generateKeyPairForVoter()
        print(self.voter_keys[0])

    @classmethod
    def _generateKeyPairForVoter(self):
        self.voter_keys = []
        for i in range(NUM_OF_VOTER):
            voter_private_key = keys.UmbralPrivateKey.gen_key()
            voter_public_key = voter_private_key.get_pubkey()
            self.voter_keys.append({"public": voter_public_key, "private": voter_private_key})

    