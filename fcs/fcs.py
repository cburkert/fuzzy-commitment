import hashlib
import secrets
from typing import Any, Callable, Generic, Optional, Tuple, TypeVar

from BitVector import BitVector
import bchlib


BCH_POLYNOMIAL = 8219

K = TypeVar('K')


class FCS(Generic[K]):
    """Fuzzy commitment scheme"""

    def __init__(self, n: int, t: int,
                 extractor: Optional[Callable[[K], BitVector]] = None) -> None:
        self.n = n
        self.t = t
        if extractor is None:
            extractor = self.byte_extractor
        self.extractor = extractor
        self.bch = bchlib.BCH(BCH_POLYNOMIAL, self.t)
        self.k = self.n - self.bch.ecc_bits  # systematic code

    @classmethod
    def byte_extractor(cls, value: Any) -> BitVector:
        value_bytes = b""
        try:
            value_bytes = bytes(value)
        except TypeError as e:
            raise TypeError("Type %s is not directly convertible to bytes. "
                            "You need to specifiy a custom extractor."
                            % type(value), e)
        return BitVector(hexstring=value_bytes.hex())

    def commit_raw(self, message: bytes,
                   witness: BitVector) -> 'Commitment':
        assert len(message) == (self.k + 7) // 8
        ecc = self.bch.encode(message)
        codeword = message + ecc
        codeword_bv = BitVector(hexstring=codeword.hex())
        # TODO check if those bit string should not be rather
        # of the same length to protect the witness
        assert len(witness) == self.n
        assert len(codeword_bv) >= len(witness)
        commitment = Commitment(
            hashlib.sha256(message).digest(),
            codeword_bv ^ witness,
        )
        return commitment

    def commit_random_message_raw(self, witness: BitVector) -> 'Commitment':
        # As long as the encoded key is longer than the witness,
        # the latter is protected.
        key = secrets.token_bytes((self.k + 7) // 8)
        return self.commit_raw(key, witness)

    def commit(self, witness: K,
               message: Optional[bytes] = None) -> 'Commitment':
        if message:
            return self.commit_raw(message, self.extractor(witness))
        else:
            return self.commit_random_message_raw(self.extractor(witness))

    def verify_raw(self, commitment: 'Commitment',
                   candidate: BitVector) -> Tuple[bool, bytes]:
        codeword_cand = candidate ^ commitment.auxiliar
        codeword_cand_bytes = bytes.fromhex(
            codeword_cand.get_bitvector_in_hex())
        bitflips, msg_cand, _ = self.bch.decode(
            codeword_cand_bytes[:-self.bch.ecc_bytes],
            codeword_cand_bytes[-self.bch.ecc_bytes:]
        )
        msg_cand = bytes(msg_cand)[-((self.k + 7) // 8):]
        msg_match = secrets.compare_digest(
            commitment.pseudonym,
            hashlib.sha256(msg_cand).digest()
        )
        # use & for constant time and (no shortcut)
        return (msg_match & (bitflips != -1), msg_cand)

    def verify(self, commitment: 'Commitment',
               candidate: K) -> Tuple[bool, bytes]:
        return self.verify_raw(commitment, self.extractor(candidate))


class Commitment(object):
    def __init__(self, pseudonym: bytes, auxiliar: BitVector) -> None:
        self.pseudonym = pseudonym
        self.auxiliar = auxiliar
