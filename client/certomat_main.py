from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
import datetime
import uuid
import json
import os.path
import sys
import datetime
import getopt

sys.path.insert(0, sys.path[0]+'..\\..\\library')

import certomat_config
import certomat_crypto


class config():
   def __init__(self, app_version, serial_number):
      self.data = {}
      self.data['global_config'] = {}
      self.data['certificate_config'] = {}
      self.data['global_config']['serial_number'] = serial_number

def set_backend(config_data):
   backend = config_data['global_config']['backend']
   if backend == 'default_backend':
      backend_obj=default_backend()
   else:
      backend_obj=default_backend()
   return backend_obj

def file_exists(file_name):
   exists = os.path.isfile(file_name)
   return exists

#def version():
   version = config_obj.app_version
   return version 

#def config_load():
   certomat_config.load(config_obj)
   return

#def generate_request():
   req_text = certomat_crypto.generate_request(config_obj, backend_obj)
   return

def main(config_obj, request_obj, argv):
   common_name = ''
  # try:
  #   opts, args = getopt.getopt(argv,"hvc:",["common_name="])
  #    opts, args = getopt.getopt(argv,"hvc:",["common_name="])
  # except getopt.GetoptError:
  #    print('test.py -c <common_name>')
  #    sys.exit(2)
  # for opt, arg in opts:
  #    if opt in ("-h", "--help"):
  #       print('usage: certomat.py -h')
  #       sys.exit()
  #    elif opt in ("-c", "--common_name"):
  #       common_name = arg
  #    elif opt in ("-v", "--version"):
  #       print(version())
  #config_obj.data['certificate_config']['common_name'] = common_name

   subject_obj = certomat_crypto.set_subject_name(config_obj)
   private_key_obj = certomat_crypto.set_private_key(config_obj, backend_obj)
   private_key_txt = certomat_crypto.pem_encode_private_key(private_key_obj)
   
   hash_obj = certomat_crypto.set_hash_name(config_obj)
   certificate_lifetime_obj = certomat_crypto.set_certificate_lifetime(config_obj)
   
   csr_obj = certomat_crypto.set_csr(private_key_obj, subject_obj, hash_obj, backend_obj)
   req_txt = certomat_crypto.pem_encode_csr(csr_obj)
   

   with open("private_key.pem", "w") as req:
      req.write(private_key_txt)

   with open("certomat.req", "wb") as req:
      req.write(req_txt)


app_version = 'client.0013alpha'
serial_number = certomat_crypto.set_serial_number()
config_obj = config(app_version, serial_number)
request_obj = config(app_version, serial_number)
config_obj = certomat_config.load(config_obj)
backend_obj = set_backend(config_obj.data)

with open("certomat.log", "a") as log:
   log.write('Certomat ' + app_version + ' certificate generated ' + datetime.datetime.now().__str__() + '\n')

if __name__ == "__main__":
   main(config_obj, request_obj, sys.argv[1:])



