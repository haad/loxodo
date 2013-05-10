import os
import sys
from optparse import OptionParser
import getpass
import readline
import cmd
import re
import time
import hashlib
import base64
import errno
from socket import error as socket_error

from pprint import pprint
from os import getcwd

from flask import Flask, session, redirect, url_for, escape, request, render_template
from flask.ext.mail import Mail, Message

from ...db.vault import Vault
from ...config import config, RECIPIENTS, DEFAULT_MAIL_SENDER, MAIL_SERVER, MAIL_PORT

class Webloxodo(Flask):
  """
  Manages Loxodo configuration from loxodo_conf.json file.
  """
  def __init__(self, name):
    self.app = Flask(__name__)
    self.mail = Mail(self.app)
    self.vault_file=self.db_path()
    self.vault_format=self.db_format()
    self.vault = None
    self.password = None
    # set the secret key.  keep this really secret:
    self.app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'
    self.app.debug = self.app_debug()

  # Get IP address on which Loxodo app should be running
  def web_host(self):
    return config.web_host

  # DB vault Path
  def db_path(self):
    return config.db_path

  # DB format string
  def db_format(self):
    return config.db_format

  # Application debug switch
  def app_debug(self):
      return config.debug

  # Sent email to recipients with simple message when user was added to DB
  def send_add_email(self, to, user, url):
    msg = Message("Password added to WebLoxodo Password Manager", sender = DEFAULT_MAIL_SENDER, recipients = to)
    msg.body = "User="+user+" with  Url="+url+" was added to WebLoxodo Password managers"
    try:
      self.mail.send(msg)
    except socket_error as serr:
      print "Sent email failed"+str(serr.errno)

def datetimeformat(value, format='%H:%M / %d-%m-%Y'):
    str_time = time.gmtime(value)
    return time.strftime(format, str_time)

def get_html_id(record_id):
    # Base64 encode sha256 hash from entry passed to this routine use only 10 chars from it that should be enough.
    return base64.b64encode(hashlib.sha256(str(record_id).encode('utf-8','replace')).hexdigest())[4:20]

def del_entry(id=None):
  if id == None:
    return redirect(url_for('mod'))

  vault_records = webloxo.vault.records[:]
  for record in vault_records:
    if get_html_id(record.last_mod) == id:
      vault_records.remove(record)

  webloxo.vault.records=vault_records
  webloxo.vault.write_to_file(webloxo.vault_file, webloxo.password)
  return redirect(url_for('mod'))

webloxo = Webloxodo(__name__)

@webloxo.app.route('/')
def index():
    if 'logged_in' in session:
        name = escape(session['logged_in'])
    else:
        name = None
    return render_template('index.html', name=name)

@webloxo.app.route('/add', methods=['GET', 'POST'])
def add():
  # It might be a good idea to encode passwords in base64 so we do not have
  # them in plaintext in html and use javascript to decode them.
  if ('logged_in' in session) and (webloxo.vault) and (request.method == 'GET'):
    return render_template('adde.html')
  if request.method == 'POST':
    entry = webloxo.vault.Record.create()
    # Add some validations here group, user, password must exist
    entry.title = request.form['title']
    entry.group = request.form['group']
    entry.user = request.form['user']
    entry.passwd = request.form['pass']
    entry.notes = request.form['notes']
    entry.url = request.form['url']
    # Add new entry to vault
    webloxo.vault.records.append(entry)
    # Save changes to vault
    webloxo.vault.write_to_file(webloxo.vault_file, webloxo.password)
    webloxo.send_add_email(RECIPIENTS, entry.user, entry.url)
  return redirect(url_for('index'))

@webloxo.app.route('/mod', methods=['GET', 'POST'])
def mod():
  if ('logged_in' in session) and (webloxo.vault) and (request.method == 'GET'):
    vault_records = webloxo.vault.records[:]
    return render_template('mod_list.html', vault_records=vault_records)
  if request.method == 'POST':
    entry_id = request.form['mod_radio']
    vault_records = webloxo.vault.records[:]

    pprint(request.form)
    for record in vault_records:
      if get_html_id(record.last_mod) == entry_id:
          if request.form['button'] == "Modify":
            return redirect(url_for('mod_entry', id=entry_id))
          else:
            del_entry(id=entry_id)
            vault_records = webloxo.vault.records[:]

    return render_template('mod_list.html', vault_records=vault_records)

@webloxo.app.route('/mod_entry/<id>', methods=['GET', 'POST'])
def mod_entry(id=None):
  if id == None:
    return redirect(url_for('mod'))

  if ('logged_in' in session) and (webloxo.vault) and (request.method == 'GET'):
    vault_records = webloxo.vault.records[:]
    for record in vault_records:
      if get_html_id(record.last_mod) == id:
        return render_template('mod_entry.html', record=record)
    return redirect(url_for('mod'))

  if request.method == 'POST':
    vault_records = webloxo.vault.records[:]
    for record in vault_records:
      if get_html_id(record.last_mod) == id:
        record.title = request.form['title']
        record.group = request.form['group']
        record.user = request.form['user']
        record.passwd = request.form['pass']
        record.notes = request.form['notes']
        record.url = request.form['url']
        # Save changes to vault
        webloxo.vault.write_to_file(webloxo.vault_file, webloxo.password)
    return redirect(url_for('mod'))

@webloxo.app.route('/list')
def list():
  # It might be a good idea to encode passwords in base64 so we do not have
  # them in plaintext in html and use javascript to decode them.
  if ('logged_in' in session) and (webloxo.vault):
    vault_records = webloxo.vault.records[:]
    return render_template('liste.html', vault_records=vault_records)

@webloxo.app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
      return redirect(url_for('index'))
    if request.method == 'POST':
        webloxo.password=request.form['password'].encode('utf-8','replace')
        webloxo.vault_file=request.form['vault_path']
        try:
          create_f=request.form['vault_create']
        except KeyError:
          create_f="0"

        if not os.path.isfile(webloxo.vault_file):
          if (create_f == "1"):
            Vault.create(webloxo.password, filename=webloxo.vault_file, format=webloxo.vault_format)
          else:
            return render_template('err.html', err_msg="Vault doesn't exist, please use correct path or check Create new vault check.")
        try:
          webloxo.vault = Vault(webloxo.password, filename=webloxo.vault_file, format=webloxo.vault_format)
        except Vault.BadPasswordError:
            return render_template('err.html', err_msg="Bad password.")
        except Vault.VaultVersionError:
            return render_template('err.html', err_msg="This is not a PasswordSafe V4 Vault.")
        except Vault.VaultFormatError:
            return render_template('err.html', err_msg="Vault integrity check failed.")

        if webloxo.vault != None:
          session['logged_in'] = request.form['password']
        return redirect(url_for('index'))
    return render_template('open.html', vault_p=webloxo.db_path())

@webloxo.app.route('/logout')
def logout():
    # remove the username from the session if its there
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@webloxo.app.errorhandler(404)
def internal_error(error):
    return render_template('404.html'), 404

@webloxo.app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == "Loxodo.frontends.web.loxodo":
    webloxo.app.jinja_env.filters['datetimeformat'] = datetimeformat
    webloxo.app.jinja_env.filters['get_html_id'] = get_html_id

    if not webloxo.app.debug:
      import logging
      from logging.handlers import RotatingFileHandler
      file_handler = RotatingFileHandler('/tmp/webloxo.log', 'a', 1 * 1024 * 1024, 10)
      file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
      webloxo.app.logger.setLevel(logging.INFO)
      file_handler.setLevel(logging.INFO)
      webloxo.app.logger.addHandler(file_handler)
      webloxo.app.logger.info('Web Loxodo startup')

    webloxo.app.run(host=webloxo.web_host())
