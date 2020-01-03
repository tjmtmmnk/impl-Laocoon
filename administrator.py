from typing import Dict, List, Tuple

from umbral.config import set_default_curve
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.kfrags import KFrag
from umbral.pre import Capsule, encrypt, generate_kfrags
from umbral.signing import Signer

from bulletinboard import BulletinBoard

NUM_OF_VOTER = 5
NUM_OF_CANDIDATE = 3


class Administrator:
    def __init__(self):
        set_default_curve()
        self.bb = BulletinBoard.get_instance()
        self.private_key = UmbralPrivateKey.gen_key()
        self.public_key = self.private_key.get_pubkey()
        self.singning_key = UmbralPrivateKey.gen_key()
        self.verifying_key = self.singning_key.get_pubkey()
        self.signer = Signer(private_key=self.private_key)
        self.voter_keys = []

    def setup(self, cand_public_keys: UmbralPublicKey):
        self._generate_key_pair_for_voter()
        re_enc_keys = self._generate_re_enc_key_admin_to_voter()

        self.bb.append({"admin_public_key": self.public_key})
        self.bb.append({"admin_re_enc_keys": re_enc_keys})
        self.bb.append({"cand_public_key": cand_public_keys})
        self.bb.append({"hash_algorithm": "SHA256"})

    def credential_dispatch(self):
        for voter_key in self.voter_keys:
            credential = self._generate_credential(voter_key["public"])
            ciphertext, capsule = self._encrypt_credential_and_voter_short_private_key(
                credential,
                voter_key["private"]
            )
            # TODO: send to proxy

    def _generate_credential(self,
                             voter_short_public_key: UmbralPublicKey
                             ) -> Tuple[UmbralPublicKey, Signer]:
        signature = self.signer(voter_short_public_key.to_bytes())
        return (voter_short_public_key, signature)

    def _encrypt_credential_and_voter_short_private_key(self,
                                                        credential: Tuple[UmbralPublicKey, Signer],
                                                        private_key: UmbralPrivateKey
                                                        ) -> Tuple[bytes, Capsule]:
        credential_bytes = credential[0].to_bytes() + bytes(credential[1])
        private_key_bytes = private_key.to_bytes()
        return encrypt(self.public_key, credential_bytes + private_key_bytes)

    def get_public_key(self):
        return self.public_key

    def _generate_key_pair_for_voter(self):
        for i in range(NUM_OF_VOTER):
            voter_short_private_key = UmbralPrivateKey.gen_key()
            voter_short_public_key = voter_short_private_key.get_pubkey()
            self.voter_keys.append(
                {
                    "public": voter_short_public_key,
                    "private": voter_short_private_key
                }
            )

    def _generate_re_enc_key_admin_to_voter(self) -> List[KFrag]:
        re_enc_keys = []
        for key in self.voter_keys:
            re_enc_key = generate_kfrags(
                delegating_privkey=self.private_key,
                signer=self.signer,
                receiving_pubkey=key["public"],
                threshold=1,
                N=1)

            re_enc_keys.append(re_enc_key)
        return re_enc_keys
