import unittest
import os, sys

lib_path = os.path.abspath('../../Loxodo/crypto/twofish')
sys.path.append(lib_path)

from twofish import Twofish

testkey = b'\xD4\x3B\xB7\x55\x6E\xA3\x2E\x46\xF2\xA2\x82\xB7\xD4\x5B\x4E\x0D\x57\xFF\x73\x9D\x4D\xC9\x2C\x1B\xD7\xFC\x01\x70\x0C\xC8\x21\x6F'
testdat = b'\x90\xAF\xE9\x1B\xB2\x88\x54\x4F\x2C\x32\xDC\x23\x9B\x26\x35\xE6'

class TestCryptoTwofish(unittest.TestCase):
  def test_encrypt(self):
    twofish = Twofish(testkey)
    assert b'l\xb4V\x1c@\xbf\n\x97\x05\x93\x1c\xb6\xd4\x08\xe7\xfa' == twofish.encrypt(testdat)

  def test_decrypt(self):
    twofish = Twofish(testkey)
    assert testdat == twofish.decrypt(b'l\xb4V\x1c@\xbf\n\x97\x05\x93\x1c\xb6\xd4\x08\xe7\xfa')

if __name__ == '__main__':
    unittest.main()
