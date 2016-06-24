from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask, request, jsonify, Response, render_template 
import datetime
import uuid
import yaml
import json
import os.path
import certomat_config
import certomat_ca

global config_data
global private_key_obj
global app_version

class certificate:
   def __init__(self, serial_number):
      self.config_data = dict()
      self.config_data['serial_number'] = serial_number

def set_backend():
   backend = config_data['backend']
   if backend == 'default_backend':
      backend=default_backend()
   else:
      backend=default_backend()
   return backend

def set_hash_name(hash_name):
   hash_name = config_data['hash_name']
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

def set_private_key(algo_name):
   if algo_name == 'secp256r1':
      private_key_obj = ec.generate_private_key(ec.SECP256R1, backend)
   elif algo_name == 'secp384r1':
       private_key_obj = ec.generate_private_key(ec.SECP384R1, backend)
   elif algo_name == 'secp521r1':
       private_key_obj = ec.generate_private_key(ec.SECP521R1, backend)
   elif algo_name == 'rsa2048':
      private_key_obj = rsa.generate_private_key(65537, 2048, backend)
   elif algo_name == 'rsa4096':
      private_key_obj = rsa.generate_private_key(65537, 4096, backend)
   else:
      private_key_obj = rsa.generate_private_key(65537, 4096, backend)
   return private_key_obj

def set_public_key(private_key_obj):
    public_key_obj = private_key.public_key()
    return public_key_obj

def set_subject_name(common_name):
   subject_name_obj = x509.Name([
      x509.NameAttribute(NameOID.COUNTRY_NAME, config_data['country_name']),
      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config_data['state_or_province']),
      x509.NameAttribute(NameOID.LOCALITY_NAME, config_data['city_or_locality']),
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, config_data['organization']),
      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config_data['organizational_unit']),
      x509.NameAttribute(NameOID.COMMON_NAME, common_name),
      x509.NameAttribute(NameOID.EMAIL_ADDRESS, config_data['email_address'])
      ,])
   return subject_name_obj

def set_csr(private_key_obj, subject_obj, hash_obj):
    csr_obj = x509.CertificateSigningRequestBuilder().subject_name(subject_obj).sign(private_key_obj, hash_obj, backend)
    return csr_obj

def sign_cert(self_signed, private_key_obj, csr_obj, serial_number, cert_lifetime, ca_issuer_name, hash_obj):
   builder_obj = x509.CertificateBuilder()
   builder_obj = builder_obj.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_issuer_name)]))
   builder_obj = builder_obj.not_valid_before(datetime.datetime.utcnow())
   builder_obj = builder_obj.not_valid_after(datetime.datetime.utcnow() + cert_lifetime)
   builder_obj = builder_obj.serial_number(serial_number)

   if self_signed == True:
      builder_obj = builder_obj.public_key(private_key_obj.public_key())

   else:
      builder_obj = builder_obj.public_key(csr_obj.public_key())

   builder_obj = builder_obj.subject_name(csr_obj.subject)
   builder_obj = builder_obj.add_extension(x509.BasicConstraints(ca=self_signed, path_length=None), critical=True,)
   builder_obj = builder_obj.sign(private_key_obj, hash_obj, backend)

   return builder_obj

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

def file_exists(file_name):
   exists = os.path.isfile(file_name)
   return exists

app_version = '.0000004pre-alpaca'
config_data = dict()
config_data = certomat_config.load(config_data)
backend = set_backend()

print(config_data.get('app_version', ''))

if file_exists(config_data['private_key_file']):
   with open(config_data['private_key_file'], "rb") as key_file:
      private_key_obj = serialization.load_pem_private_key(key_file.read(), password=None, backend=backend)
else:
   initialize_ca()
   
app = Flask(__name__)

@app.route('/')
def root():
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/version')
def version():
   version = config_data.get('app_version', '')
   return version 

@app.route('/config-init')
def config_init():
   certomat_ca.init(config_data)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-save')
def config_save():
   certomat_config.save(config_data)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-load')
def config_load():
   certomat_config.load(config_data)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-default')
def config_default():
   certomat_config.default(app_version, set_serial_number(), config_data)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/test')
def test():

   request = certificate(set_serial_number())

   request.config_data['hash_obj'] = set_hash_name(config_data['hash_name'])
   request.config_data['cert_lifetime'] = config_data['certificate_lifetime_in_days']

   certificate_lifetime_obj = datetime.timedelta(days=int(request.config_data['cert_lifetime']))
   
   request.config_data['ca_issuer_name'] = 'Test Root 1'
   subject_name = set_subject_name('test')
   private_key2 = set_private_key('secp256r1')
   csr2 = set_csr(private_key2, subject_name2, hash_name)
   client_cert = sign_cert(False, private_key2, csr2, serial_number2, certificate_lifetime_obj, ca_issuer_name, )
   cert_txt = client_cert.public_bytes(serialization.Encoding.PEM).decode(encoding="utf-8", errors="strict")\
      + private_key2.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, \
      encryption_algorithm=serialization.NoEncryption()).decode(encoding="utf-8", errors="strict")

   resp = Response(response=cert_txt, status=200, mimetype="application/json")
   return(resp)

@app.route('/csr')
def csr():
    return render_template('form_submit.html')

@app.route('/certificate', methods=['POST'])
def certificate():
    csr=request.form['csr']
    return render_template('form_action.html', csr=csr)

if __name__ == '__main__':
   app.run(host=config_data['ip_address'], port=config_data['port_number'])

