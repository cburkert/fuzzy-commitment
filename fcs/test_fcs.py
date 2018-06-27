import unittest
import secrets

import fcs


class TestFCS(unittest.TestCase):
    def setUp(self):
        self.threshold = 2
        self.cs = fcs.FCS(256, 128, self.threshold)
        self.witness = secrets.token_bytes(32)
        self.commitment = self.cs.commit(self.witness)

    def random_flip_witness(self, numbits: int) -> bytes:
        witness_mod = bytearray(self.witness)
        for i in range(numbits):
            byte_num = secrets.randbelow(len(self.witness))
            bit_num = secrets.randbelow(8)
            witness_mod[byte_num] ^= (1 << bit_num)
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


if __name__ == '__main__':
    unittest.main()
