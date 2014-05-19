#
# Loxodo -- Password Safe V3 compatible Password Vault
# Copyright (C) 2008 Christoph Sommer <mail@christoph-sommer.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

import hashlib
import struct
from hmac import HMAC
import random
import os
import tempfile
import time
import uuid

from ..crypto.twofish.twofish_ecb import TwofishECB
from ..random_password import random_password

class VaultVer4(object):
  """
    PWD database version 4 access class
  """
  def __init__ (self):
    self.db_version_tag = b'PWS4'
    self.db_end_tag = b'PWS4-EOFPWS4-EOF'
    self.db_ptag = [b'PSTW', b'PSAE']
    self.db_dbtag = b'PWDB'
    self.db_format = b'v4'

    self.db_filename = None
    self.db_filehandle = None

    self.db_v4_passwds = []

  def db_open(self, filename=None, mode='rb'):
    self.db_filename = filename
    if self.db_filename:
      self.db_filehandle = open(filename, mode)

  def db_close(self):
    self.db_filename = None
    self.db_filehandle.close()

  def db_end_data(self):
    # Write end tag only if file was opened for write.
    if self.db_filehandle.mode == 'wb':
      self.db_filehandle.write(self.db_end_tag)

  # Read length of bytes from db file version 3
  def db_read_data (self, length):
    return self.db_filehandle.read(length)

  # Write length of bytes to db file version 3
  def db_write_data (self, data):
    return self.db_filehandle.write(data)

  # Test if we have correct begin tag for version 3 db
  def db_test_bg_tag (self, tag):
    if (self.db_version_tag == tag):
      return True
    else:
      return False

  # Test if we got correct end tag for db v3
  def db_test_end_tag (self, tag):
    if (self.db_end_tag == tag):
      return True
    else:
      return False

  def db_get_stretched_passwd(self, vault, password):
    for item in self.db_v4_passwds:
      if item['orig'] == '1':
        stretched_user_pass = vault._stretch_password(password, vault.f_salt, vault.f_iter)
        cipher = TwofishECB(stretched_user_pass)
        if hashlib.sha256(cipher.decrypt(item['passwd'])).digest() == vault.f_sha_ps:
          return cipher.decrypt(item['passwd'])
    return ""

  # Read header from file to Vault
  def db_read_header(self, password, vault):
    vault.f_tag = self.db_filehandle.read(4)  # TAG: magic tag

    if vault.f_tag != self.db_version_tag:
      raise DBError("Wrong database version string giving up.")

    # Add all user passwords/auth_tags from vault db to list
    while True:
      auth_tag = self.db_filehandle.read(4)
      if auth_tag == self.db_dbtag:
        break
      self.db_v4_passwds.append({'auth': auth_tag, 'passwd': self.db_filehandle.read(32), 'orig': '1'})

    vault.f_salt = self.db_filehandle.read(32)  # SALT: SHA-256 salt
    vault.f_iter = struct.unpack("<L", self.db_filehandle.read(4))[0]  # ITER: SHA-256 keystretch iterations
    vault.f_sha_ps = self.db_filehandle.read(32) # H(P'): SHA-256 hash of stretched passphrase
    vault.f_b1 = self.db_filehandle.read(16)  # B1
    vault.f_b2 = self.db_filehandle.read(16)  # B2
    vault.f_b3 = self.db_filehandle.read(16)  # B3
    vault.f_b4 = self.db_filehandle.read(16)  # B4
    vault.f_iv = self.db_filehandle.read(16)  # IV: initialization vector of Twofish CBC

  # Create empty Vault for v3 db
  # password argument is secondary password from user
  def db_create_header(self, password, vault):

    assert isinstance(password, bytes)

    vault.f_tag = self.db_version_tag
    vault.f_salt = vault.urandom(32)
    vault.f_iter = 2048

    # Database version 4 uses one master password which is random generated
    # and secondary passwords to encrypt them.
    # XXX What about master normal password ?
    rand_p = random_password()
    rand_p.password_length = 32
    master_passwd = bytes(rand_p.generate_password(), 'UTF-8')

    stretched_master_password = vault._stretch_password(master_passwd, vault.f_salt, vault.f_iter)
    vault.f_sha_ps = hashlib.sha256(stretched_master_password).digest()

    cipher = TwofishECB(stretched_master_password)
    vault.f_b1 = cipher.encrypt(vault.urandom(16))
    vault.f_b2 = cipher.encrypt(vault.urandom(16))
    vault.f_b3 = cipher.encrypt(vault.urandom(16))
    vault.f_b4 = cipher.encrypt(vault.urandom(16))
    key_k = cipher.decrypt(vault.f_b1) + cipher.decrypt(vault.f_b2)
    key_l = cipher.decrypt(vault.f_b3) + cipher.decrypt(vault.f_b4)

    vault.f_iv = vault.urandom(16)

    hmac_checker = HMAC(key_l, b"", hashlib.sha256)

    # No records yet
    vault.f_hmac = hmac_checker.digest()

    # Encrypt master password with user one
    stretched_user_pass = vault._stretch_password(password, vault.f_salt, vault.f_iter)
    user_cipher = TwofishECB(stretched_user_pass)
    self.db_v4_passwds = [{'auth': self.db_ptag[0], 'passwd': user_cipher.encrypt(stretched_master_password), 'orig': '1'}]

  def db_write_header(self, vault, password):
    # FIXME: choose new SALT, B1-B4, IV values on each file write? Conflicting Specs!
    assert isinstance(password, bytes)

    # write boilerplate
    self.db_filehandle.write(vault.f_tag)

    for item in self.db_v4_passwds:
       self.db_filehandle.write(item['auth'])
       self.db_filehandle.write(item['passwd'])

    self.db_filehandle.write(self.db_dbtag)
    self.db_filehandle.write(vault.f_salt)
    self.db_filehandle.write(struct.pack("<L", vault.f_iter))

    self.db_filehandle.write(vault.f_sha_ps)

    self.db_filehandle.write(vault.f_b1)
    self.db_filehandle.write(vault.f_b2)
    self.db_filehandle.write(vault.f_b3)
    self.db_filehandle.write(vault.f_b4)

    self.db_filehandle.write(vault.f_iv)

  #
  # Go through all loaded passwords from file and try to find working one.
  # Working one == password which decypts it's saved passwd correctly (it's digest is same as sha_ps)
  # When we have working password use decrypted master password, and encypt it with new user password.
  #
  def db_add_user(self, vault, existing_user_password, new_user_password):
    for item in self.db_v4_passwds:
      if item['orig'] == '1':
        stretched_user_pass = vault._stretch_password(existing_user_password, vault.f_salt, vault.f_iter)
        cipher = TwofishECB(stretched_user_pass)
        if hashlib.sha256(cipher.decrypt(item['passwd'])).digest() == vault.f_sha_ps:
            new_stretched_user_pass = vault._stretch_password(new_user_password, vault.f_salt, vault.f_iter)
            newu_cipher = TwofishECB(new_stretched_user_pass)
            self.db_v4_passwds.append({'auth': self.db_ptag[0], 'passwd': newu_cipher.encrypt(cipher.decrypt(item['passwd'])), 'orig': '0'})
