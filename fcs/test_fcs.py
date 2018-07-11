import unittest
import random
import secrets

import fcs


class TestFCS(unittest.TestCase):
    def setUp(self):
        self.threshold = 2
        self.witness = secrets.token_bytes(32)
        self.cs = fcs.FCS(len(self.witness)*8, self.threshold)
        self.commitment = self.cs.commit(self.witness)

    def random_flip_witness(self, numbits: int) -> bytes:
        witness_mod = bytearray(self.witness)
        bit_nums = random.sample(range(len(self.witness) * 8), numbits)
        for bit_num in bit_nums:
            witness_mod[bit_num // 8] ^= (1 << (bit_num % 8))
        return bytes(witness_mod)

    def test_unaltered_witness(self):
        valid, key = self.cs.verify(self.commitment, self.witness)
        self.assertTrue(valid)

    def test_altered_tolerable(self):
        witness_mod = self.random_flip_witness(self.threshold)
        valid, key = self.cs.verify(self.commitment, witness_mod)
        self.assertTrue(valid)

    def test_altered_intolerable(self):
        witness_mod = self.random_flip_witness(self.threshold + 1)
        valid, key = self.cs.verify(self.commitment, witness_mod)
        self.assertFalse(valid)


class TestFCSTwo(unittest.TestCase):
    def setUp(self):
        witlen = 1152
        self.threshold = 277
        self.witness = secrets.token_bytes((witlen+7)//8)
        self.cs = fcs.FCS(len(self.witness)*8, self.threshold)
        self.commitment = self.cs.commit(self.witness)

    def random_flip_witness(self, numbits: int) -> bytes:
        witness_mod = bytearray(self.witness)
        bit_nums = random.sample(range(len(self.witness) * 8), numbits)
        for bit_num in bit_nums:
            witness_mod[bit_num // 8] ^= (1 << (bit_num % 8))
        return bytes(witness_mod)

    def test_unaltered_witness(self):
        valid, key = self.cs.verify(self.commitment, self.witness)
        self.assertTrue(valid)

    def test_altered_tolerable(self):
        witness_mod = self.random_flip_witness(self.threshold)
        valid, key = self.cs.verify(self.commitment, witness_mod)
        self.assertTrue(valid)

    def test_altered_intolerable(self):
        witness_mod = self.random_flip_witness(self.threshold+200)
        valid, key = self.cs.verify(self.commitment, witness_mod)
        self.assertFalse(valid)


if __name__ == '__main__':
    unittest.main()
