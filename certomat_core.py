from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
import datetime
import uuid

def set_hash_name(config_data):
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

def set_private_key(config_data, backend_obj):
   if config_data['algorithm_name'] == 'secp256r1':
      private_key_obj = ec.generate_private_key(ec.SECP256R1, backend_obj)
   elif config_data['algorithm_name'] == 'secp384r1':
       private_key_obj = ec.generate_private_key(ec.SECP384R1, backend_obj)
   elif config_data['algorithm_name'] == 'secp521r1':
       private_key_obj = ec.generate_private_key(ec.SECP521R1, backend_obj)
   elif config_data['algorithm_name'] == 'rsa2048':
      private_key_obj = rsa.generate_private_key(65537, 2048, backend_obj)
   elif config_data['algorithm_name'] == 'rsa4096':
      private_key_obj = rsa.generate_private_key(65537, 4096, backend_obj)
   else:
      private_key_obj = rsa.generate_private_key(65537, 4096, backend_obj)
   return private_key_obj

def set_public_key(private_key_obj):
    public_key_obj = private_key.public_key()
    return public_key_obj

def set_subject_name(config_data, common_name):
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

def set_csr(private_key_obj, subject_obj, hash_obj, config_data, backend_obj):
    csr_obj = x509.CertificateSigningRequestBuilder().subject_name(subject_obj).sign(private_key_obj, hash_obj, backend_obj)
    return csr_obj

def sign_cert(self_signed, private_key_obj, csr_obj, serial_number, cert_lifetime, ca_issuer_name, hash_obj, backend_obj):
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
   builder_obj = builder_obj.sign(private_key_obj, hash_obj, backend_obj)

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

def init(config_data, backend_obj):
   subject_obj = set_subject_name(config_data, config_data['common_name'])
   issuer_name = config_data['common_name']
   private_key_obj = set_private_key(config_data, backend_obj)
   hash_obj = set_hash_name(config_data)
   certificate_lifetime_obj = datetime.timedelta(days=config_data['certificate_lifetime_in_days'])

   csr_obj = set_csr(private_key_obj, subject_obj, hash_obj, config_data, backend_obj)
   root_cert_obj = sign_cert(True, private_key_obj, csr_obj, config_data['serial_number'], certificate_lifetime_obj, issuer_name, hash_obj, backend_obj)

   with open("root_cert.der", "wb") as f:
       f.write(root_cert_obj.public_bytes(serialization.Encoding.DER))
   with open("csr.pem", "wb") as f:
       f.write(csr_obj.public_bytes(serialization.Encoding.PEM))
   return

def process(config_data, backend_obj):
   request = certificate()
   request.config_data['hash_obj'] = set_hash_name(config_data['hash_name'])
   request.config_data['cert_lifetime'] = config_data['certificate_lifetime_in_days']
   certificate_lifetime_obj = datetime.timedelta(days=int(request.config_data['cert_lifetime'])) 
   request.config_data['ca_issuer_name'] = 'Test Root 1'
   subject_name = set_subject_name('test')
   private_key2 = set_private_key('secp256r1')
   csr2 = set_csr(private_key2, subject_name2, hash_name)
   client_cert = sign_cert(False, private_key2, csr2, serial_number2, certificate_lifetime_obj, ca_issuer_name)
   cert_txt = client_cert.public_bytes(serialization.Encoding.PEM).decode(encoding="utf-8", errors="strict")\
      + private_key2.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, \
      encryption_algorithm=serialization.NoEncryption()).decode(encoding="utf-8", errors="strict")
   return
