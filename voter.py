from typing import Dict, Tuple

from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.pre import Capsule, decrypt
from umbral.signing import Signer

from config import SIZE_OF_PUBLIC_KEY


class Voter:
    def __init__(self, short_public_key, short_private_key):
        self.short_public_key = short_public_key
        self.short_private_key = short_private_key
        self.private_key = UmbralPrivateKey.gen_key()
        self.public_key = self.private_key.get_pubkey()

    def receive_ciphertext_from_proxy(self,
                                      ciphertext: Dict[str, Tuple[bytes, Capsule]]):
        (credential, private_key) = self._decrypt_ciphertext(ciphertext)
        self.short_public_key = credential[:SIZE_OF_PUBLIC_KEY]
        self.short_private_key = private_key
        signature_for_public_key = credential[SIZE_OF_PUBLIC_KEY:]

    def _decrypt_ciphertext(self,
                            ciphertext: Dict[str, Tuple[bytes, Capsule]]) -> Tuple[Tuple[UmbralPublicKey, Signer], UmbralPrivateKey]:
        """decrypt ciphertext

        Arguments:
            ciphertext {Dict[str, Tuple[bytes, Capsule]]}

        Returns:
            Tuple[Tuple[UmbralPublicKey, Signer], UmbralPrivateKey] -- (credential, private key)
        """
        (enc_credential, c_capsule) = ciphertext["credential"]
        (enc_private_key, p_capsule) = ciphertext["private_key"]

        credential = decrypt(ciphertext=enc_credential,
                             capsule=c_capsule,
                             decrypting_key=self.private_key)
        private_key = decrypt(ciphertext=enc_private_key,
                              capsule=p_capsule,
                              decrypting_key=self.private_key)

        return (credential, private_key)
