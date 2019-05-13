"""TODO
"""
import hashlib
import secrets
from typing import Any, Callable, Generic, Optional, TypeVar

from BitVector import BitVector
import bchlib


BCH_POLYNOMIAL = 8219

K = TypeVar('K')  # pylint: disable=invalid-name


def _byte_extractor(value: Any) -> BitVector:
    """Extracts a BitVector from a bytes-convertable value.

    Args:
        value: A value of any type that can be converted into bytes.

    Returns:
        A BitVector extracted from the value's byte representation.

    Raises:
        TypeError: Given value cannot be converted to bytes.
    """
    value_bytes = b""
    try:
        value_bytes = bytes(value)
    except TypeError as error:
        raise TypeError("Type %s is not directly convertible to bytes. "
                        "You need to specifiy a custom extractor."
                        % type(value), error)
    return BitVector(hexstring=value_bytes.hex())


class FCS(Generic[K]):
    """Fuzzy commitment scheme.

    This implementation follows the proposal by Juels and Wattenberg [1]
    with additions by Kelkboom et al. [2].

    [1] http://doi.acm.org/10.1145/319709.319714
    [2] https://ieeexplore.ieee.org/abstract/document/5634099/
    """

    def __init__(self, witness_nbits: int, tolerance: int,
                 extractor: Optional[Callable[[K], BitVector]] = None) -> None:
        """Initializes FCS.

        Args:
            witness_nbits: Length of the witness in bits.
            tolerance: Number of changed bits tolerated by the scheme.
            extractor: Optional function to extract a BitVector from K.
        """
        self._witlen = witness_nbits
        if extractor is None:
            extractor = _byte_extractor
        self._extractor = extractor
        self._bch = bchlib.BCH(BCH_POLYNOMIAL, tolerance)
        # Length of codeword: self._witlen + self._bch.ecc_bits
        # This is due to the systematic code property.

    def _commit_raw(self, message: bytes,
                    witness: BitVector) -> 'Commitment':
        """Commit on a raw binary message.

        Args:
            message: A binary message to commit to.
            witness: A witness to the commitment.

        Returns:
            A Commitment.

        Raises:
            ValueError: Witness is too long.
        """
        if len(witness) > self._witlen:
            raise ValueError("Witness exceeds the given maximum length "
                             f"({len(witness)}>{self._witlen}).")
        ecc = self._bch.encode(message)
        codeword = message + ecc
        codeword_bv = BitVector(hexstring=codeword.hex())
        # The codeword needs to be larger than or equally long as the witness
        # to maintain the HIDE property of the commitment.
        assert len(codeword_bv) >= len(witness)
        # Reverse BitVectors for xor-ing to achieve right-padding
        # of the witness. This is to minimize the errors introduced
        # to the parity (ecc) which leads to indeterministic
        # false-positive verifications.
        commitment = Commitment(
            hashlib.sha256(message).digest(),
            (codeword_bv.reverse() ^ witness.reverse()).reverse(),
        )
        return commitment

    def _commit_random_message_raw(self, witness: BitVector) -> 'Commitment':
        """Same as _commit_raw but uses a random message."""
        # As long as the encoded key is longer than the witness,
        # the latter is protected. Hence round up to the next byte.
        key_len = (self._witlen + 7) // 8
        key = secrets.token_bytes(key_len)
        return self._commit_raw(key, witness)

    def commit(self, witness: K,
               message: Optional[bytes] = None) -> 'Commitment':
        """Create a fuzzy commitment over a given otherwise random message.

        Args:
            witness: Witness used for the commitment.
            message: Optional binary message to commit to.

        Returns:
            A Commitment.

        Raises:
            ValueError: Witness is too long.
        """
        if message:
            commitment = self._commit_raw(message, self._extractor(witness))
        else:
            commitment = self._commit_random_message_raw(
                self._extractor(witness))
        return commitment

    def _open_raw(self, commitment: 'Commitment',
                  candidate: BitVector) -> Optional[bytes]:
        """See open."""
        codeword_cand = (commitment.auxiliar.reverse()
                         ^ candidate.reverse()).reverse()
        codeword_cand_bytes = bytes.fromhex(
            codeword_cand.get_bitvector_in_hex())
        bitflips, msg_cand, _ = self._bch.decode(
            codeword_cand_bytes[:-self._bch.ecc_bytes],
            codeword_cand_bytes[-self._bch.ecc_bytes:]
        )
        msg_match = secrets.compare_digest(
            commitment.pseudonym,
            hashlib.sha256(msg_cand).digest()
        )
        # use & for constant time and (no shortcut)
        is_valid = msg_match & (bitflips != -1)
        return bytes(msg_cand) if is_valid else None

    def open(self, commitment: 'Commitment',
             candidate: K) -> Optional[bytes]:
        """Tries to opens the commitment with the candidate.

        Args:
            commitment: Commitment to open.
            candidate: Candidate to open with.

        Returns:
            The committed message if the candidate is close enough to the
            commitment or None otherwise.
        """
        return self._open_raw(commitment, self._extractor(candidate))

    def verify(self, commitment: 'Commitment',
               candidate: K) -> bool:
        """Verifies the given candidate against the commitment.

        Args:
            commitment: Commitment to verify against.
            candidate: Candidate to verify.

        Returns:
            True if the candidate is close enough to the commitment, False
            otherwise.
        """
        return self.open(commitment, candidate) is not None


class Commitment(object):
    """Commitment"""
    def __init__(self, pseudonym: bytes, auxiliar: BitVector) -> None:
        self.pseudonym = pseudonym
        self.auxiliar = auxiliar
