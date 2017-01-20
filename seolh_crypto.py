from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
import datetime
import uuid
import random
import string

def set_hash_name(config_obj):
   hash_name = config_obj.data['root_cert_config']['hash_name']
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
   algorithm_name = config_obj.data['root_cert_config']['algorithm_name']
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

def set_subject_name(config_obj, common_name):
   subject_name_obj = x509.Name([
      x509.NameAttribute(NameOID.COUNTRY_NAME, config_obj.data['root_cert_config']['country_name']),
      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config_obj.data['root_cert_config']['state_or_province']),
      x509.NameAttribute(NameOID.LOCALITY_NAME, config_obj.data['root_cert_config']['city_or_locality']),
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, config_obj.data['root_cert_config']['organization']),
      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config_obj.data['root_cert_config']['organizational_unit']),
      x509.NameAttribute(NameOID.COMMON_NAME, common_name),
      x509.NameAttribute(NameOID.EMAIL_ADDRESS, config_obj.data['root_cert_config']['email_address'])
      ,])
   return subject_name_obj

def set_csr(private_key_obj, subject_obj, hash_obj, backend_obj):
    csr_obj = x509.CertificateSigningRequestBuilder().subject_name(subject_obj).sign(private_key_obj, hash_obj, backend_obj)
    return csr_obj

def sign_cert(self_signed, private_key_obj, csr_obj, cert_lifetime_obj, hash_obj, config_obj, backend_obj):
   utcnow = datetime.datetime.utcnow()
   serial_number_int = int(set_serial_number())
   serial_number_str = hex(serial_number_int)[2:]

   save_path = 'certificates\\'
   
   builder_obj = x509.CertificateBuilder()
   builder_obj = builder_obj.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, config_obj.data['root_cert_config']['common_name'])]))
   builder_obj = builder_obj.not_valid_before(utcnow)
   builder_obj = builder_obj.not_valid_after(utcnow + cert_lifetime_obj)
   builder_obj = builder_obj.serial_number(serial_number_int)

   if self_signed == True:
      builder_obj = builder_obj.public_key(private_key_obj.public_key())

   else:
      builder_obj = builder_obj.public_key(csr_obj.public_key())

   builder_obj = builder_obj.subject_name(csr_obj.subject)
   builder_obj = builder_obj.add_extension(x509.BasicConstraints(ca=self_signed, path_length=None), critical=True, )
   builder_obj = builder_obj.sign(private_key_obj, hash_obj, backend_obj)
   
   with open(config_obj.data['service_config']['database'], "a") as database:
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

def set_random_string():
   random_string = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15))
   return random_string

def set_certificate_lifetime(config_obj):
   certificate_lifetime_obj = datetime.timedelta(days=config_obj.data['root_cert_config']['certificate_lifetime_in_days'])
   return certificate_lifetime_obj


