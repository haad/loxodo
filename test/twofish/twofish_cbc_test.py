import unittest
import os, sys

lib_path = os.path.abspath('../../Loxodo/crypto/twofish')
sys.path.append(lib_path)

from twofish import Twofish
from twofish_cbc import TwofishCBC

testkey = b"Now Testing Crypto-Functions...."
testivc = b"Initialization V"
testenc = b"Passing nonsense through crypt-API, will then do assertion check"
testdec = b"\x38\xd1\xe3\xb1\xe6\x0d\x41\xa7\xe7\xba\xf1\xeb\x34\x4b\xc3\xdb\x88\x38\xf5\x47\x41\x15\x3f\x26\xa4\x2d\x53\xd8\xd2\x80\x25\x0a\xf3\xe4\xbe\xe4\xba\xe1\xeb\x18\x18\x66\x8a\xa6\xe2\xd0\x2b\x6e\x62\x36\x91\xf7\x72\x28\x5e\xc6\x40\x89\x70\x91\x2c\x35\x71\x39"

class TestCryptoTwofishCBC(unittest.TestCase):
  def test_encrypt_cbc(self):
    twofishcbc = TwofishCBC(testkey, testivc)
    assert twofishcbc.encrypt(testdec) == testenc

  def test_decrypt_cbc(self):
    twofishcbc = TwofishCBC(testkey, testivc)
    assert twofishcbc.decrypt(testenc) == testdec

if __name__ == '__main__':
    unittest.main()
