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

def save_config():
   tempdata = {
   'app_version' : config_data['app_version'],
   'config_file' : config_data['config_file'],
   'backend' : config_data['backend'], 
   'initialized' : config_data['initialized'], 
   'common_name' : config_data['common_name'],
   'subject_alternate_names' : config_data['subject_alternate_names'],
   'serial_number' : config_data['serial_number'],
   'email_address' : config_data['email_address'],
   'organization' : config_data['organization'],
   'organizational_unit' : config_data['organizational_unit'],
   'city_or_locality' : config_data['city_or_locality'],
   'state_or_province' : config_data['state_or_province'],
   'country_name' : config_data['country_name'],
   'algorithm_name' : config_data['algorithm_name'],
   'hash_name' : config_data['hash_name'],
   'certificate_lifetime_in_days' : config_data['certificate_lifetime_in_days'],
   'private_key_file' : config_data['private_key_file'],
   'private_key_format' : config_data['private_key_format'],
   'private_key_password' : config_data['private_key_password'],
   'root_certificate_file_name' : config_data['root_certificate_file_name'],
   'root_certificate_format' : config_data['root_certificate_format'],
   'fqdn' : config_data['fqdn'],
   'ip_address' : config_data['ip_address'],
   'database' : config_data['database'],
   'port_number' : config_data['port_number'],
   'auth_psk' : config_data['auth_psk']}
   with open("cert-o-matic.yaml", "w") as stream:
     stream.write(yaml.dump(tempdata, default_flow_style=False))
   return

def load_config():
   temp_data = {}
   with open("cert-o-matic.yaml", "r") as stream:
      temp_data = yaml.load(stream)

   config_data['app_version'] = temp_data['app_version']
   config_data['config_file'] = temp_data['config_file']
   config_data['backend'] = temp_data['backend'] 
   config_data['initialized'] = temp_data['initialized'] 
   config_data['common_name'] = temp_data['common_name']
   config_data['subject_alternate_names'] = temp_data['subject_alternate_names']
   config_data['serial_number'] = int(temp_data['serial_number'])
   config_data['email_address'] = temp_data['email_address']
   config_data['organization'] = temp_data['organization']
   config_data['organizational_unit'] = temp_data['organizational_unit']
   config_data['city_or_locality'] = temp_data['city_or_locality']
   config_data['state_or_province'] = temp_data['state_or_province']
   config_data['country_name'] = temp_data['country_name']
   config_data['algorithm_name'] = temp_data['algorithm_name']
   config_data['hash_name'] = temp_data['hash_name']
   config_data['certificate_lifetime_in_days'] = temp_data['certificate_lifetime_in_days']
   config_data['private_key_file'] = temp_data['private_key_file']
   config_data['private_key_format'] = temp_data['private_key_format']
   config_data['private_key_password'] = temp_data['private_key_password']
   config_data['root_certificate_file_name'] = temp_data['root_certificate_file_name']
   config_data['root_certificate_format'] = temp_data['root_certificate_format']
   config_data['fqdn'] = temp_data['fqdn']
   config_data['ip_address'] = temp_data['ip_address']
   config_data['database'] = temp_data['database']
   config_data['port_number'] = temp_data['port_number']
   config_data['auth_psk'] = temp_data['auth_psk']      
   return config_data

def default_config(app_version):
   config_data['app_version'] = app_version
   config_data['config_file'] = 'cert-o-matic.yaml'
   config_data['backend'] = 'default_backend' 
   config_data['initialized'] = True
   config_data['common_name'] = 'certomatic test ca'
   config_data['subject_alternate_names'] = 'localhost'
   config_data['serial_number'] = set_serial_number()
   config_data['email_address'] = 'root@localhost'
   config_data['organization'] = 'Flying Circus'
   config_data['organizational_unit'] = 'Elephant Wrangler Union'
   config_data['city_or_locality'] = 'Pullman'
   config_data['state_or_province'] = 'WA'
   config_data['country_name'] = 'US'
   config_data['algorithm_name'] = 'rsa4096'
   config_data['hash_name'] = 'sha512'
   config_data['certificate_lifetime_in_days'] = '30'
   config_data['private_key_file'] = 'root_private_key.der'
   config_data['private_key_format'] = 'der'
   config_data['private_key_password'] = None
   config_data['root_certificate_file_name'] = 'root_cert.der'
   config_data['root_certificate_format'] = 'der'
   config_data['fqdn'] = 'localhost'
   config_data['ip_address'] = '127.0.0.1'
   config_data['database'] = None
   config_data['port_number'] = 80
   config_data['auth_psk'] = None  
   return config_data

def set_serial_number():
   serial_number = int(uuid.uuid4())
   return serial_number

def file_exists(file_name):
   exists = os.path.isfile(file_name)
   return exists

def initialize_ca():
   subject_obj = set_subject_name(config_data['common_name'])
   issuer_name = config_data['common_name']
   private_key_obj = set_private_key(config_data['algorithm_name'])
   hash_obj = set_hash_name(config_data['hash_name'])
   certificate_lifetime_obj = datetime.timedelta(days=int(config_data['certificate_lifetime_in_days']))


   csr_obj = set_csr(private_key_obj, subject_obj, hash_obj)
   root_cert_obj = sign_cert(True, private_key_obj, csr_obj, config_data['serial_number'], certificate_lifetime_obj, issuer_name, hash_obj)

   with open("root_cert.der", "wb") as f:
       f.write(root_cert_obj.public_bytes(serialization.Encoding.DER))
   with open("csr.pem", "wb") as f:
       f.write(csr_obj.public_bytes(serialization.Encoding.PEM))

app_version = '.0000004pre-alpaca'
config_data = dict()
config_data = load_config()
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
   return 'ok'

@app.route('/version')
def version():
   version = config_data.get('app_version', '')
   return version 


@app.route('/ca')
def ca():
    
   initialize_ca()

   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/save')
def save():
   save_config()
   # resp_txt = json.dumps('ok')
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/load')
def load():
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/defaultconfig')
def defaultconfig():
   default_config(app_version)
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

