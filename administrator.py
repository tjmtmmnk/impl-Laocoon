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
        self.signer = signing.Signer(private_key=self.private_key)

    def setup(self):
        voter_keys = self._generate_key_pair_for_voter()
        re_enc_keys = self._generate_re_enc_key_admin_to_voter(voter_keys)
        print(re_enc_keys)
        
    def get_public_key(self):
        return self.public_key

    def _generate_key_pair_for_voter(self):
        voter_keys = []
        for i in range(NUM_OF_VOTER):
            voter_short_private_key = keys.UmbralPrivateKey.gen_key()
            voter_short_public_key = voter_short_private_key.get_pubkey()
            voter_keys.append(
                {
                "public": voter_short_public_key,
                "private": voter_short_private_key
                }
            )
        return voter_keys

    def _generate_re_enc_key_admin_to_voter(self, voter_keys):
        re_enc_keys = []
        for key in voter_keys:
            re_enc_key = pre.generate_kfrags(
                    delegating_privkey=self.private_key,
                    signer=self.signer,
                    receiving_pubkey=key["public"],
                    threshold=1,
                    N=1)

            re_enc_keys.append(re_enc_key)
        return re_enc_keys
