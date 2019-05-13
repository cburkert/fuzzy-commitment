# pylint: disable=missing-docstring,invalid-name
import unittest
import random
import secrets

from BitVector import BitVector

import fcs


def random_flip(witness: bytes, numbits: int) -> bytes:
    witness_mod = bytearray(witness)
    bit_nums = random.sample(range(len(witness) * 8), numbits)
    for bit_num in bit_nums:
        witness_mod[bit_num // 8] ^= (1 << (bit_num % 8))
    return bytes(witness_mod)


class TestFCS(unittest.TestCase):
    def setUp(self):
        self.threshold = 2
        self.witness = secrets.token_bytes(32)
        self.cs = fcs.FCS(len(self.witness)*8, self.threshold)
        self.commitment = self.cs.commit(self.witness)

    def test_unaltered_witness(self):
        valid = self.cs.verify(self.commitment, self.witness)
        self.assertTrue(valid)

    def test_altered_tolerable(self):
        witness_mod = random_flip(self.witness, self.threshold)
        valid = self.cs.verify(self.commitment, witness_mod)
        self.assertTrue(valid)

    def test_altered_intolerable(self):
        witness_mod = random_flip(self.witness, self.threshold + 1)
        valid = self.cs.verify(self.commitment, witness_mod)
        self.assertFalse(valid)


class TestFCSTwo(unittest.TestCase):
    def setUp(self):
        witlen = 1152
        self.threshold = 277
        self.witness = secrets.token_bytes((witlen+7)//8)
        self.cs = fcs.FCS(len(self.witness)*8, self.threshold)
        self.commitment = self.cs.commit(self.witness)

    def test_unaltered_witness(self):
        valid = self.cs.verify(self.commitment, self.witness)
        self.assertTrue(valid)

    def test_altered_tolerable(self):
        witness_mod = random_flip(self.witness, self.threshold)
        valid = self.cs.verify(self.commitment, witness_mod)
        self.assertTrue(valid)

    def test_altered_intolerable(self):
        witness_mod = random_flip(self.witness, self.threshold+1)
        valid = self.cs.verify(self.commitment, witness_mod)
        self.assertFalse(valid)


def int_extractor(value: int) -> BitVector:
    value_bytes = int.to_bytes(value, length=1, byteorder='little')
    return BitVector(hexstring=value_bytes.hex())


class TestFCSCustomExtractor(unittest.TestCase):
    def setUp(self):
        self.threshold = 1
        self.cs = fcs.FCS[int](
            8, self.threshold,
            extractor=int_extractor,
        )
        self.witness = 3
        self.message = b"\xcb"
        self.commitment = self.cs.commit(self.witness, message=self.message)

    def test_unaltered_witness(self):
        msg = self.cs.open(self.commitment, self.witness)
        self.assertEqual(msg, self.message)

    def test_altered_tolerable(self):
        msg = self.cs.open(self.commitment, 2)  # one bit changed
        self.assertEqual(msg, self.message)

    def test_altered_intolerable(self):
        msg = self.cs.open(self.commitment, 4)  # three bits changed
        self.assertEqual(msg, None)


if __name__ == '__main__':
    unittest.main()
