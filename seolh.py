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
import adict

global config_data
global private_key_obj

class certificate_authority(dict):
   def __init__(self):
      self.data = {}
   def __setitem__(self, key, value):
      self.data[key] = value
   def __getitem__(self, key):
      return self.data[key]

def set_hash_name(hash_name):
   hash_name = config_data['hash_name']
   if hash_name == 'sha256':
       hash_name = hashes.SHA256()
   elif hash_name == 'sha384':
       hash_name = hashes.SHA384()
   elif hash_name == 'sha512':
      hash_name = hashes.SHA512()
   elif algo_name == 'whirlpool':
      hash_name = hashes.Whirlpool()
   else:
      hash_name = hashes.SHA256()
   return hash_name

def set_algorithm_name(algo_name):
   if algo_name == 'secp256r1':
      algorithm_name = ec.generate_private_key(ec.SECP256R1, backend)
   elif algo_name == 'secp384r1':
       algorithm_name = ec.generate_private_key(ec.SECP384R1, backend)
   elif algo_name == 'secp521r1':
       algorithm_name = ec.generate_private_key(ec.SECP521R1, backend)
   elif algo_name == 'rsa2048':
      algorithm_name = rsa.generate_private_key(65537, 2048, backend)
   elif algo_name == 'rsa4096':
      algorithm_name = rsa.generate_private_key(65537, 4096, backend)
   else:
      algorithm_name = rsa.generate_private_key(65537, 4096, backend)
   return(algorithm_name)

def set_public_key(private_key):
    public_key = private_key.public_key()
    return(public_key)

def set_subject_name(common_name):
   subject_name = x509.Name([
      x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
      x509.NameAttribute(NameOID.LOCALITY_NAME, u"West Sacramento"),
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Personal"),
      x509.NameAttribute(NameOID.COMMON_NAME, common_name),])
   return subject_name

def set_csr(private_key_obj, subject_obj, hash_obj):
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject_obj).sign(private_key_obj, hash_obj, backend)
    return(csr)

def sign_cert(self_signed, private_key_obj, csr_obj, serial_number, cert_lifetime, ca_issuer_name, hash_obj):
   builder = x509.CertificateBuilder()
   builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_issuer_name)]))
   builder = builder.not_valid_before(datetime.datetime.utcnow())
   builder = builder.not_valid_after(datetime.datetime.utcnow() + cert_lifetime)
   builder = builder.serial_number(serial_number)

   if self_signed == True:
      builder = builder.public_key(private_key_obj.public_key())

   else:
      builder = builder.public_key(csr_obj.public_key())

   builder = builder.subject_name(csr_obj.subject)
   builder = builder.add_extension(x509.BasicConstraints(ca=self_signed, path_length=None), critical=True,)
   builder = builder.sign(private_key_obj, hash_obj, backend)

   return builder

def pem_encode_private_key(private_key):
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    text = pem.decode('ascii')
    return(text)

def pem_encode_public_key(public_key):
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    text = pem.decode('ascii')
    return(text)

def pem_encode_csr(csr):
    pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
    return(pem)

def save_config():
   tempdata = {
   'app_version' : config_data[app_version],
   'config_file' : config_data[config_file],
   'back_end' : config_data[back_end], 
   'initialized' : config_data[initialized], 
   'common_name' : config_data[common_name],
   'subject_alternate_names' : config_data[subject_alternate_names],
   'serial_number' : config_data[serial_number],
   'email_address' : config_data[email_address],
   'organization' : config_data[organization],
   'organizational_unit' : config_data[organizational_unit],
   'city_or_locality' : config_data[city_or_locality],
   'state_or_province' : config_data[state_or_province],
   'country_name' : config_data[country_name],
   'algorithm_name' : config_data[algorithm_name],
   'hash_name' : config_data[hash_name],
   'certificate_lifetime_in_days' : config_data[certificate_lifetime_in_days],
   'private_key_file' : config_data[private_key],
   'private_key_format' : config_data[private_key_format],
   'private_key_password' : config_data[private_key_password],
   'root_certificate_file_name' : config_data[root_certificate_file_name],
   'root_certificate_format' : config_data[root_certificate_format],
   'fqdn' : config_data[fqdn],
   'ip_address' : config_data[ip_address],
   'database' : config_data[database],
   'port_number' : config_data[port_number],
   'auth_psk' : config_data[auth_psk]}
   with open("seolh-ca-config2.yaml", "w") as stream:
     stream.write(yaml.dump(tempdata, default_flow_style=False))
   return

def load_config():
   temp_data = {}
   with open("seolh-ca-config.yaml", "r") as stream:
      temp_data = yaml.load(stream)

   config_data['app_version'] = temp_data['app_version']
   config_data['config_file'] = temp_data['config_file']
   config_data['back_end'] = temp_data['back_end'] 
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
   config_data['certificate_lifetime_in_days'] = datetime.timedelta(days=int(temp_data['certificate_lifetime_in_days']))
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

def set_serial_number():
   serial_number = int(uuid.uuid4())
   return serial_number



config_data = dict()
config_data = load_config()
print(config_data.get('app_version', ''))
with open(config_data['private_key_file'], "rb") as key_file:
   private_key_obj = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

   
app = Flask(__name__)

@app.route('/')
def root():
   return "ok"

@app.route('/version')
def version():
   version = config_data.get('app_version', '')
   return version 


@app.route('/ca')
def ca():
    
   subject_obj = set_subject_name(config_data['common_name'])
   issuer_name = config_data['common_name']
   algorithm_obj = set_algorithm_name(config_data['algorithm_name'])
   hash_obj = set_hash_name(config_data['hash_name'])

   csr_obj = set_csr(private_key_obj, subject_obj, hash_obj)
   root_cert_obj = sign_cert(True, private_key_obj, csr_obj, config_data['serial_number'], config_data['certificate_lifetime_in_days'], issuer_name, hash_obj)

   resp = Response(response="ok", status=200, mimetype="application/json")
   return(resp)

@app.route('/save')
def save():
   config_data.save_config()
   resp_txt = json.dumps('ok')
   resp = Response(response=resp_txt, status=200, mimetype="application/json")
   return(resp)

@app.route('/load')
def load():
   print
   resp = Response(response=resp_txt, status=200, mimetype="application/json")
   return(resp)

@app.route('/test')
def test():
    hash_name = set_hash_name('sha512')
    cert_lifetime = datetime.timedelta(1, 0, 0)
    ca_issuer_name = 'Test Root 1'
    serial_number2 = int(uuid.uuid4())
    subject_name2 = set_subject_name('test')
    private_key2 = set_private_key('secp256r1')
    csr2 = set_csr(private_key2, subject_name2, hash_name)
    client_cert = sign_cert(False, private_key2, csr2, serial_number2, cert_lifetime, ca_issuer_name, )
    cert_txt = client_cert.public_bytes(serialization.Encoding.PEM).decode(encoding="utf-8", errors="strict") + private_key2.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, \
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
   backend = default_backend()
   app.run(host="0.0.0.0", port=int("80"))

