from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import json
import os.path
import certomat_config
import certomat_core
import datetime
import sys

for arg in sys.argv: 
   print arg

class config():
   def __init__(self, app_version):
      self.app_version = app_version
      self.serial_number = certomat_core.set_serial_number()
      self.self_signed = bool
      self.data = {}
      self.data['ca_config'] = {}
      self.data['client_config'] = {}

def set_backend(config_data):
   backend = config_data['ca_config']['backend']
   if backend == 'default_backend':
      backend_obj=default_backend()
   else:
      backend_obj=default_backend()
   return backend_obj

def file_exists(file_name):
   exists = os.path.isfile(file_name)
   return exists

app_version = 'client.0011alpha'
config_obj = config(app_version)
request_obj = config(app_version)
config_obj = certomat_config.load(config_obj)
backend_obj = set_backend(config_obj.data)

if file_exists(config_obj.data['ca_config']['private_key_file']):
   with open(config_obj.data['ca_config']['private_key_file'], "rb") as key_file:
      private_key_obj = serialization.load_pem_private_key(key_file.read(), password=None, backend=backend_obj)
else:
   certomat_core.initalize(config_obj, backend_obj)

with open("certomat.log", "a") as log:
   log.write('Certomat ' + app_version + ' startup ' + datetime.datetime.now().__str__() + '\n')

def version():
   version = config_obj.app_version
   return version 

def initalize():
   certomat_core.initalize(config_obj, backend_obj)
   return

def config_load():
   certomat_config.load(config_obj)
   return

def generate_request():
   req_text = certomat_core.generate_request(config_obj, backend_obj)
   return







