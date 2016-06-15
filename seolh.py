from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import constant_time
import datetime
import uuid
from yaml import load, dump

appversion = "SEOLH .004"

def set_hash_name(hash_name):
   if hash_name == 'sha256':
       hash_name = hashes.SHA256()
   elif hash_name == 'sha384':
       hash_name = hashes.SHA384()
   elif hash_name == 'sha512':
      hash_name = hashes.SHA512()
   elif algo_name == 'whirlpool':
      hash_name = hashes.Whirlpool()
   else:
      print('cannot find hash')
      hash_name = hashes.SHA512()
   return hash_name


def gen_private_key(algo_name):
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
   else:
      print('cannot find algo')
      private_key = rsa.generate_private_key(65537, 4096, backend)
   return(private_key)

def gen_public_key(private_key):
    public_key = private_key.public_key()
    return(public_key)

def build_subject_name(common_name):
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"West Sacramento"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Personal"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
    return subject_name

def gen_csr(private_key, subject_name):
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject_name).sign(private_key, hashes.SHA256(), backend)
    return(csr)

def sign_cert(self_signed, private_key, csr, serial_number, cert_lifetime, ca_issuer_name, hash_name):
   builder = x509.CertificateBuilder()
   builder = builder.issuer_name(ca_issuer_name)
   builder = builder.not_valid_before(datetime.datetime.utcnow())
   builder = builder.not_valid_after(datetime.datetime.utcnow() + cert_lifetime)
   builder = builder.serial_number(int(uuid.uuid4()))

   if self_signed == True:
      builder = builder.public_key(private_key.public_key())
      build_subject_name(common_name)
      builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_issuer_name),]))

   else:
      builder = builder.public_key(csr.public_key())
      build_subject_name(common_name)
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

def save_configuration(ca_issuer_name, cert_lifetime, hash_name):
   with open("seolh-ca-config.yaml", "w") as f:
      f.write(dump({'common_name': ca_issuer_name, 'organization': 'Home', 'organizational_unit': 'Test', 'state_or_province': 'CA', 'country_name': 'US', 'city_or_locality': 'West Sacramento',\
'signature_algorithm': 'SHA-256', 'signature_hash_algorithm': 'SHA256','certificate_lifetime': '1','certificate_version': 'V3','thumbprint_algorithm': 'SHA1', 'email_address': 'test@local'}))
   return

def load_configuration(ca_issuer_name, cert_lifetime, hash_name):
   with open("seolh-ca-config.yaml", "r") as f:
      print(load(f.read()))
   return

backend = default_backend()
subject_name = build_subject_name(u'test')
private_key1 = gen_private_key('secp256r1')
private_key2 = gen_private_key('secp256r1')
csr = gen_csr(private_key2, subject_name)
serial_number = int(uuid.uuid4())
cert_lifetime = datetime.timedelta(1, 0, 0)
ca_issuer_name = u'Test Root 1'
hash_name = 'sha512'

root_cert = sign_cert(True, private_key1, csr, serial_number, cert_lifetime, ca_issuer_name, hash_name)
client_cert = sign_cert(False, private_key2, csr, serial_number, cert_lifetime, ca_issuer_name, hash_name)

with open("root_cert.der", "wb") as f:
    f.write(root_cert.public_bytes(serialization.Encoding.DER))

with open("client_cert.der", "wb") as f:
    f.write(client_cert.public_bytes(serialization.Encoding.DER))

#save_configuration(ca_issuer_name, cert_lifetime, hash_name)
#load_configuration(ca_issuer_name, cert_lifetime, hash_name)
