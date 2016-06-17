from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
import datetime
import uuid
import yaml
import json
from flask import Flask, request, jsonify, Response, render_template

appversion = "SEOLH .007"
backend = default_backend()

def set_hash_name(hash_name):
   if hash_name == 'sha256':
       hash_name = hashes.SHA256()
   elif hash_name == 'sha384':
       hash_name = hashes.SHA384()
   elif hash_name == 'sha512':
      hash_name = hashes.SHA512()
   elif algo_name == 'whirlpool':
      hash_name = hashes.Whirlpool()
   return hash_name

def set_private_key(algo_name):
   if algo_name == 'secp256r1':
      private_key = ec.generate_private_key(ec.SECP256R1, backend)
   elif algo_name == 'secp384r1':
       private_key = ec.generate_private_key(ec.SECP384R1, backend)
   elif algo_name == 'secp521r1':
       private_key = ec.generate_private_key(ec.SECP521R1, backend)
   elif algo_name == 'rsa2048':
      private_key = rsa.generate_private_key(65537, 2048, backend)
   elif algo_name == 'rsa4096':
      private_key = rsa.generate_private_key(65537, 4096, backend)
   return(private_key)

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

def set_csr(private_key, subject_name, hash_name):
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject_name).sign(private_key, hash_name, backend)
    return(csr)

def sign_cert(self_signed, private_key, csr, serial_number, cert_lifetime, ca_issuer_name, hash_name):
   builder = x509.CertificateBuilder()
   builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_issuer_name)]))
   builder = builder.not_valid_before(datetime.datetime.utcnow())
   builder = builder.not_valid_after(datetime.datetime.utcnow() + cert_lifetime)
   builder = builder.serial_number(int(uuid.uuid4()))

   if self_signed == True:
      builder = builder.public_key(private_key.public_key())

   else:
      builder = builder.public_key(csr.public_key())

   builder = builder.subject_name(csr.subject)
   builder = builder.add_extension(x509.BasicConstraints(ca=self_signed, path_length=None), critical=True,)
   builder = builder.sign(private_key, hash_name, backend)

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

def save_configuration(initialized, common_name, email_address, organization, organizational_unit, city_or_locality, state_or_province, country_name, signature_algorithm, signature_hash_algorithm, \
                       certificate_lifetime, thumbprint_algorithm):
   data = {
      'initialized' : initialized, 
      'common_name' : common_name,
      'email_address' : email_address,
      'organization' : organization,
      'organizational_unit' : organizational_unit,
      'city_or_locality' : city_or_locality,
      'state_or_province' : state_or_province,
      'country_name' : country_name,
      'signature_algorithm' : signature_algorithm,
      'signature_hash_algorithm' : signature_hash_algorithm,
      'certificate_lifetime' : certificate_lifetime,
      'thumbprint_algorithm' : thumbprint_algorithm,
      'private_key_file_name' : private_key_file_name,
      'private_key_format' : private_key_format,
      'private_key_password' : private_key_password,
      'root_certificate_file_name' : root_certificate_file_name,
      'root_certificate_format' : root_certificate_format,
      }

   with open("seolh-ca-config.yaml", "w") as stream:
      stream.write(yaml.dump(data, default_flow_style=False))
   return

def load_configuration(ca_issuer_name, cert_lifetime, hash_name):
   data = {}
   with open("seolh-ca-config.yaml", "r") as stream:

      data = yaml.load(stream)
   return data

app = Flask(__name__)

@app.route('/version')
def version():
    return(appversion)

@app.route('/ca')
def ca():
   backend = default_backend()
   hash_name = set_hash_name('sha512')
   cert_lifetime = datetime.timedelta(1, 0, 0)
   ca_issuer_name = 'Test Root 1'
   serial_number1 = int(uuid.uuid4())
   subject_name1 = set_subject_name(u'Test Root 1')
   private_key1 = set_private_key('secp521r1')
   csr1 = set_csr(private_key1, subject_name1, hash_name)
   root_cert = sign_cert(True, private_key1, csr1, serial_number1, cert_lifetime, ca_issuer_name, hash_name)
   save_configuration('V3', ca_issuer_name, 'test@local', organization, organizational_unit, city_or_locality, state_or_province, country_name, signature_algorithm, signature_hash_algorithm, \
                       certificate_lifetime, thumbprint_algorithm)
   with open("root_cert.der", "wb") as f:
      f.write(root_cert.public_bytes(serialization.Encoding.DER))

  # with open("csr.pem", "wb") as f:
  #    f.write(csr1.public_bytes(serialization.Encoding.PEM))
      
   with open("root_private_key.der", "wb") as f:
      f.write(private_key1.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))

   resp = Response(response="ok", status=200, mimetype="application/json")
   return(resp)

@app.route('/save')
def save():
   save_configuration(certificate_version, common_name, email_address, organization, organizational_unit, city_or_locality, state_or_province, country_name, signature_algorithm, signature_hash_algorithm, \
                       certificate_lifetime, thumbprint_algorithm)
   resp = Response(response=cert_txt, status=200, mimetype="application/json")
   return(resp)

@app.route('/load')
def load():
   hash_name = set_hash_name('sha512')
   cert_lifetime = datetime.timedelta(1, 0, 0)
   ca_issuer_name = 'Test Root 1'
   data = load_configuration(ca_issuer_name, cert_lifetime, hash_name)
   
   #for keys,values in data.items():
   #   print(keys + ':' + str(values))
   resp_txt = json.dumps('ok')

   resp = Response(response=resp_txt, status=200, mimetype="application/json")
   return(resp)

@app.route('/test')
def test():
    backend = default_backend()
    hash_name = set_hash_name('sha512')
    cert_lifetime = datetime.timedelta(1, 0, 0)
    ca_issuer_name = 'Test Root 1'
    serial_number2 = int(uuid.uuid4())
    subject_name2 = set_subject_name('test')
    private_key2 = set_private_key('secp256r1')
    csr2 = set_csr(private_key2, subject_name2, hash_name)
    client_cert = sign_cert(False, private_key2, csr2, serial_number2, cert_lifetime, ca_issuer_name, hash_name)
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
  app.run( 
        host="0.0.0.0",
        port=int("80")
  )

