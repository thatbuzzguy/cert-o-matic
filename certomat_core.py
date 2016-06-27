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
   hash_name = config_data['ca_config']['hash_name']
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
   if config_data['ca_config']['algorithm_name'] == 'secp256r1':
      private_key_obj = ec.generate_private_key(ec.SECP256R1, backend_obj)
   elif config_data['ca_config']['algorithm_name'] == 'secp384r1':
       private_key_obj = ec.generate_private_key(ec.SECP384R1, backend_obj)
   elif config_data['ca_config']['algorithm_name'] == 'secp521r1':
       private_key_obj = ec.generate_private_key(ec.SECP521R1, backend_obj)
   elif config_data['ca_config']['algorithm_name'] == 'rsa2048':
      private_key_obj = rsa.generate_private_key(65537, 2048, backend_obj)
   elif config_data['ca_config']['algorithm_name'] == 'rsa4096':
      private_key_obj = rsa.generate_private_key(65537, 4096, backend_obj)
   else:
      private_key_obj = rsa.generate_private_key(65537, 4096, backend_obj)
   return private_key_obj

def set_public_key(private_key_obj):
    public_key_obj = private_key.public_key()
    return public_key_obj

def set_subject_name(config_data, common_name):
   subject_name_obj = x509.Name([
      x509.NameAttribute(NameOID.COUNTRY_NAME, config_data['ca_config']['country_name']),
      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config_data['ca_config']['state_or_province']),
      x509.NameAttribute(NameOID.LOCALITY_NAME, config_data['ca_config']['city_or_locality']),
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, config_data['ca_config']['organization']),
      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config_data['ca_config']['organizational_unit']),
      x509.NameAttribute(NameOID.COMMON_NAME, common_name),
      x509.NameAttribute(NameOID.EMAIL_ADDRESS, config_data['ca_config']['email_address'])
      ,])
   return subject_name_obj

def set_csr(private_key_obj, subject_obj, hash_obj, config_data, backend_obj):
    csr_obj = x509.CertificateSigningRequestBuilder().subject_name(subject_obj).sign(private_key_obj, hash_obj, backend_obj)
    return csr_obj

def sign_cert(self_signed, private_key_obj, csr_obj, serial_number, cert_lifetime, ca_issuer_name, hash_obj, backend_obj, config_data):
   utcnow = datetime.datetime.utcnow()
   serial_number_str = hex(serial_number)[2:]
   save_path = 'certificates\\'
   
   builder_obj = x509.CertificateBuilder()
   builder_obj = builder_obj.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_issuer_name)]))
   builder_obj = builder_obj.not_valid_before(utcnow)
   builder_obj = builder_obj.not_valid_after(utcnow + cert_lifetime)
   builder_obj = builder_obj.serial_number(serial_number)

   if self_signed == True:
      builder_obj = builder_obj.public_key(private_key_obj.public_key())

   else:
      builder_obj = builder_obj.public_key(csr_obj.public_key())

   builder_obj = builder_obj.subject_name(csr_obj.subject)
   builder_obj = builder_obj.add_extension(x509.BasicConstraints(ca=self_signed, path_length=None), critical=True, )
   builder_obj = builder_obj.sign(private_key_obj, hash_obj, backend_obj)

   with open(config_data['ca_config']['database'], "a") as database:
       database.write(serial_number_str + ' ' + utcnow.strftime("%d/%m/%Y %H:%M:%S") + '\n')

   with open(save_path + serial_number_str + '.der', "ab") as current_certificate:
       current_certificate.write(builder_obj.public_bytes(serialization.Encoding.DER))

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

def initalize(config_data, backend_obj):
   subject_obj = set_subject_name(config_data, config_data['ca_config']['common_name'])
   issuer_name = config_data['ca_config']['issuer_name']
   private_key_obj = set_private_key(config_data, backend_obj)
   hash_obj = set_hash_name(config_data)
   certificate_lifetime_obj = datetime.timedelta(days=config_data['ca_config']['certificate_lifetime_in_days'])

   csr_obj = set_csr(private_key_obj, subject_obj, hash_obj, config_data, backend_obj)
   root_cert_obj = sign_cert(True, private_key_obj, csr_obj, config_data['ca_config']['serial_number'], certificate_lifetime_obj, issuer_name, hash_obj, backend_obj, config_data)

   with open("root_cert.der", "wb") as f:
       f.write(root_cert_obj.public_bytes(serialization.Encoding.DER))
   with open(config_data['ca_config']['private_key_file'], "wb") as f:
       f.write(private_key_obj.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
   return

def generate_request(config_data, backend_obj, request_obj, ca_obj): 
   subject_obj = set_subject_name(config_data, 'test')
   private_key_obj = set_private_key(config_data, backend_obj)
   hash_obj = set_hash_name(config_data)
   certificate_lifetime_obj = datetime.timedelta(days=request_obj.config_data['ca_config']['certificate_lifetime_in_days'])
   ca_issuer_name = config_data['ca_config']['issuer_name']
   serial_number = set_serial_number()
   
   csr_obj = set_csr(private_key_obj, subject_obj, hash_obj, config_data, backend_obj)
   cert_txt = csr_obj.public_bytes(serialization.Encoding.PEM)
   return cert_txt

def process_request(config_data, backend_obj, request_obj, ca_obj):
   subject_obj = set_subject_name(config_data, 'test')
   private_key_obj = set_private_key(config_data, backend_obj)
   hash_obj = set_hash_name(config_data)
   certificate_lifetime_obj = datetime.timedelta(days=request_obj.config_data['ca_config']['certificate_lifetime_in_days'])
   ca_issuer_name = config_data['ca_config']['issuer_name']
   serial_number = set_serial_number()
   
   csr_obj = set_csr(private_key_obj, subject_obj, hash_obj, config_data, backend_obj)
   client_cert = sign_cert(False, private_key_obj, csr_obj, serial_number, certificate_lifetime_obj, ca_issuer_name, hash_obj, backend_obj, config_data)

   cert_txt = client_cert.public_bytes(serialization.Encoding.PEM).decode(encoding="utf-8", errors="strict")\
      + private_key_obj.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, \
      encryption_algorithm=serialization.NoEncryption()).decode(encoding="utf-8", errors="strict")
   return cert_txt

def save_request(config_data, backend_obj, request_obj, ca_obj):
   subject_obj = set_subject_name(config_data, 'test')
   private_key_obj = set_private_key(config_data, backend_obj)
   hash_obj = set_hash_name(config_data)
   serial_number = request_obj.config_data['ca_config']['serial_number']
   certificate_lifetime_obj = datetime.timedelta(days=request_obj.config_data['ca_config']['certificate_lifetime_in_days'])
   ca_issuer_name = config_data['ca_config']['issuer_name']
   
   csr_obj = set_csr(private_key_obj, subject_obj, hash_obj, config_data, backend_obj)
   client_cert = sign_cert(False, private_key_obj, csr_obj, serial_number, certificate_lifetime_obj, ca_issuer_name, hash_obj, backend_obj, config_data)

   cert_txt = client_cert.public_bytes(serialization.Encoding.PEM).decode(encoding="utf-8", errors="strict")\
      + private_key_obj.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, \
      encryption_algorithm=serialization.NoEncryption()).decode(encoding="utf-8", errors="strict")
   return cert_txt
