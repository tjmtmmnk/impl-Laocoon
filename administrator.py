from typing import Dict, List, Tuple

from umbral.config import set_default_curve
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.kfrags import KFrag
from umbral.pre import Capsule, encrypt, generate_kfrags
from umbral.signing import Signer

from voter import Voter
from bulletinboard import BulletinBoard
from config import NUM_OF_VOTER
from proxy import Proxy


class Administrator:
    _unique_instance = None

    def __new__(self):
        raise NotImplementedError('Cannot initialize via Constructor')

    @classmethod
    def __internal_new__(self):
        return super().__new__(self)

    @classmethod
    def get_instance(self):
        if not self._unique_instance:
            set_default_curve()
            self.bb = BulletinBoard.get_instance()
            self.proxy = Proxy.get_instance()
            self.private_key = UmbralPrivateKey.gen_key()
            self.public_key = self.private_key.get_pubkey()
            self.singning_key = UmbralPrivateKey.gen_key()
            self.verifying_key = self.singning_key.get_pubkey()
            self.signer = Signer(private_key=self.singning_key)
            self.voters = []
            self._unique_instance = self.__internal_new__()

        return self._unique_instance

    def setup(self, cand_public_keys: UmbralPublicKey):
        self._generate_voters()
        re_enc_keys = self._generate_re_enc_key_admin_to_voter()

        self.bb.append({"admin_public_key": self.public_key})
        self.bb.append({"admin_re_enc_keys": re_enc_keys})
        self.bb.append({"cand_public_key": cand_public_keys})
        self.bb.append({"hash_algorithm": "SHA256"})

    def credential_dispatch(self):
        for voter in self.voters:
            credential = self._generate_credential(voter.short_public_key)
            ciphertext = self._encrypt_credential_and_voter_short_private_key(
                credential,
                voter.short_private_key
            )
            self.proxy.receive_ciphertext_from_admin(ciphertext)

    def _generate_credential(self,
                             voter_short_public_key: UmbralPublicKey
                             ) -> Tuple[UmbralPublicKey, Signer]:
        """generate credential

        Arguments:
            voter_short_public_key {UmbralPublicKey}

        Returns:
            Tuple[UmbralPublicKey, Signer]
        """
        signature = self.signer(voter_short_public_key.to_bytes())
        return (voter_short_public_key, signature)

    def _encrypt_credential_and_voter_short_private_key(self,
                                                        credential: Tuple[UmbralPublicKey, Signer],
                                                        private_key: UmbralPrivateKey
                                                        ) -> Dict[str, Tuple[bytes, Capsule]]:
        """encrypt credential and voter short private key

        Arguments:
            credential {Tuple[UmbralPublicKey, Signer]}
            private_key {UmbralPrivateKey}

        Returns:
            Dict[str, Tuple[bytes, Capsule]] -- need to save Capsule
        """
        credential_bytes = credential[0].to_bytes() + bytes(credential[1])
        private_key_bytes = private_key.to_bytes()

        return {
            "credential": encrypt(self.public_key, credential_bytes),
            "private_key": encrypt(self.public_key, private_key_bytes)
        }

    def _generate_voters(self):
        for i in range(NUM_OF_VOTER):
            short_private_key = UmbralPrivateKey.gen_key()
            short_public_key = short_private_key.get_pubkey()
            voter = Voter(short_public_key, short_private_key)
            self.voters.append(voter)

    def _generate_re_enc_key_admin_to_voter(self) -> List[Dict[str, KFrag]]:
        """generate re-encrypt key from admin to (admin)voter

        Returns:
            List[Dict[int, KFrag]] -- voter id to re-encrypt
        """
        re_enc_keys = []
        for i, voter in enumerate(self.voters):
            re_enc_key = generate_kfrags(
                delegating_privkey=self.private_key,
                signer=self.signer,
                receiving_pubkey=voter.short_public_key,
                threshold=1,
                N=1)
            re_enc_keys.append({
                i: re_enc_key
            })
        return re_enc_keys
