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

def set_hash_name(config_obj):
   hash_name = config_obj.data['certificate_config']['hash_name']
   if hash_name == 'sha256':
       hash_obj = hashes.SHA256()
   elif hash_name == 'sha384':
       hash_obj = hashes.SHA384()
   elif hash_name == 'sha512':
      hash_obj = hashes.SHA512()
   elif algo_name == 'whirlpool':
      hash_obj = hashes.Whirlpool()
   else:
      hash_obj = hashes.SHA256()
   return hash_obj

def set_private_key(config_obj, backend_obj):
   algorithm_name = config_obj.data['certificate_config']['algorithm_name']
   if algorithm_name == 'secp256r1':
      private_key_obj = ec.generate_private_key(ec.SECP256R1, backend_obj)
   elif algorithm_name == 'secp384r1':
       private_key_obj = ec.generate_private_key(ec.SECP384R1, backend_obj)
   elif algorithm_name == 'secp521r1':
       private_key_obj = ec.generate_private_key(ec.SECP521R1, backend_obj)
   elif algorithm_name == 'rsa2048':
      private_key_obj = rsa.generate_private_key(65537, 2048, backend_obj)
   elif algorithm_name == 'rsa4096':
      private_key_obj = rsa.generate_private_key(65537, 4096, backend_obj)
   else:
      private_key_obj = rsa.generate_private_key(65537, 4096, backend_obj)
   return private_key_obj

def set_public_key(private_key_obj):
    public_key_obj = private_key.public_key()
    return public_key_obj

def set_subject_name(config_obj):

   if config_obj.data['certificate_config']['self_signed'] == 'true':
      subject_name_obj = x509.Name([
         x509.NameAttribute(NameOID.COUNTRY_NAME, config_obj.data['global_config']['country_name']),
         x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config_obj.data['global_config']['state_or_province']),
         x509.NameAttribute(NameOID.LOCALITY_NAME, config_obj.data['global_config']['city_or_locality']),
         x509.NameAttribute(NameOID.ORGANIZATION_NAME, config_obj.data['global_config']['organization']),
         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config_obj.data['global_config']['organizational_unit']),
         x509.NameAttribute(NameOID.COMMON_NAME, config_obj.data['certificate_config']['common_name']),
         x509.NameAttribute(NameOID.EMAIL_ADDRESS, config_obj.data['global_config']['email_address'])
         ,])
   else:      
      subject_name_obj = x509.Name([
         x509.NameAttribute(NameOID.COUNTRY_NAME, config_obj.data['certificate_config']['country_name']),
         x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config_obj.data['certificate_config']['state_or_province']),
         x509.NameAttribute(NameOID.LOCALITY_NAME, config_obj.data['certificate_config']['city_or_locality']),
         x509.NameAttribute(NameOID.ORGANIZATION_NAME, config_obj.data['certificate_config']['organization']),
         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config_obj.data['certificate_config']['organizational_unit']),
         x509.NameAttribute(NameOID.COMMON_NAME, config_obj.data['certificate_config']['fqdn']),
         x509.NameAttribute(NameOID.EMAIL_ADDRESS, config_obj.data['certificate_config']['email_address'])
         ,])
   return subject_name_obj

def set_csr(private_key_obj, subject_obj, hash_obj, backend_obj):
    csr_obj = x509.CertificateSigningRequestBuilder().subject_name(subject_obj).sign(private_key_obj, hash_obj, backend_obj)
    return csr_obj

def pem_encode_private_key(private_key_obj):
    pem = private_key_obj.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    text = pem.decode('ascii')
    return(text)

def pem_encode_public_key(private_key_obj):
    pem = private_key_obj.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    text = pem.decode('ascii')
    return(text)

def pem_encode_csr(csr):
    pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
    return(pem)

def set_serial_number():
   serial_number = int(uuid.uuid4())
   return serial_number

def set_certificate_lifetime(config_obj):
   certificate_lifetime_obj = datetime.timedelta(days=config_obj.data['certificate_config']['certificate_lifetime_in_days'])
   return certificate_lifetime_obj

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

   subject_obj = set_subject_name(config_obj)
   private_key_obj = set_private_key(config_obj, backend_obj)
   private_key_txt = pem_encode_private_key(private_key_obj)
   
   hash_obj = set_hash_name(config_obj)
   certificate_lifetime_obj = set_certificate_lifetime(config_obj)
   
   csr_obj = set_csr(private_key_obj, subject_obj, hash_obj, backend_obj)
   req_txt = pem_encode_csr(csr_obj)
   

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



