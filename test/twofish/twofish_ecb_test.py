import unittest
import os, sys

lib_path = os.path.abspath('../../Loxodo/crypto/twofish')
sys.path.append(lib_path)

from twofish import Twofish
from twofish_ecb import TwofishECB

testkey = b"Now Testing Crypto-Functions...."
testenc = b"Passing nonsense through crypt-API, will then do assertion check"
testdec = b"\x71\xbf\x8a\xc5\x8f\x6c\x2d\xce\x9d\xdb\x85\x82\x5b\x25\xe3\x8d\xd8\x59\x86\x34\x28\x7b\x58\x06\xca\x42\x3d\xab\xb7\xee\x56\x6f\xd3\x90\xd6\x96\xd5\x94\x8c\x70\x38\x05\xf8\xdf\x92\xa4\x06\x2f\x32\x7f\xbd\xd7\x05\x41\x32\xaa\x60\xfd\x18\xf4\x42\x15\x15\x56"

class TestCryptoTwofishECB(unittest.TestCase):
  def test_encrypt_ecb(self):
    twofishecb = TwofishECB(testkey)
    assert twofishecb.encrypt(testdec) == testenc

  def test_decrypt_ecb(self):
    twofishecb = TwofishECB(testkey)
    assert twofishecb.decrypt(testenc) == testdec

if __name__ == '__main__':
    unittest.main()
