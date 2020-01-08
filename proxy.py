import random
from typing import Dict, List, Tuple

from umbral.cfrags import CapsuleFrag
from umbral.kfrags import KFrag
from umbral.pre import Capsule, reencrypt

from bulletinboard import BulletinBoard
from config import NUM_OF_VOTER
from voter import Voter


class Proxy:
    _unique_instance = None

    def __new__(self):
        raise NotImplementedError('Cannot initialize via Constructor')

    @classmethod
    def __internal_new__(self):
        return super().__new__(self)

    @classmethod
    def get_instance(self):
        if not self._unique_instance:
            self.ciphertexts = []
            self._unique_instance = self.__internal_new__()

        return self._unique_instance

    def receive_ciphertext_from_admin(self, ciphertext: Dict[str, Tuple[bytes, Capsule]]):
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
        shuffled_voters = random.sample(voters, len(voters))
        re_enc_keys = BulletinBoard.get_instance().find_by_key("admin_re_enc_keys")

        for j, voter in enumerate(shuffled_voters):
            re_enc_ciphertext = self._re_encrypt_ciphertext_from_admin_to_voter(
                re_enc_key=re_enc_keys[j],
                ciphertext=self.ciphertexts[j])

    def _re_encrypt_ciphertext_from_admin_to_voter(self,
                                                   re_enc_key: KFrag,
                                                   ciphertext: Dict[str, Tuple[bytes, Capsule]]) -> Tuple[CapsuleFrag, CapsuleFrag]:
    """re encrypt ciphertext from admin to voter
    
    Arguments:
        re_enc_key {KFrag} -- from admin to voter
        ciphertext {Dict[str, Tuple[bytes, Capsule]]} -- encrypted under admin's public key
    
    Returns:
        Tuple[CapsuleFrag, CapsuleFrag] -- re encrypted ciphertext
    """
    re_enc_credential = reencrypt(kfrag=re_enc_key,
                                  capsule=ciphertext["credential"][1])

    re_enc_private_key = reencrypt(kfrag=re_enc_key,
                                   capsule=ciphertext["private_key"][1])

    return (re_enc_credential, re_enc_private_key)
