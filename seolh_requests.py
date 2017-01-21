import datetime

from cryptography.hazmat.primitives import serialization
#does this needs to be moved into crypto?

import seolh_config
import seolh_crypto
import seolh_requests

def initalize(config_obj, backend_obj):
   subject_obj = seolh_crypto.set_subject_name(config_obj, config_obj.data['root_cert_config']['common_name'])
   # issuer_name = config_obj.data['root_cert_config']['issuer_name']
   private_key_obj = seolh_crypto.set_private_key(config_obj, backend_obj)
   hash_obj = seolh_crypto.set_hash_name(config_obj)
   certificate_lifetime_obj = datetime.timedelta(days=config_obj.data['root_cert_config']['certificate_lifetime_in_days'])

   csr_obj = seolh_crypto.set_csr(private_key_obj, subject_obj, hash_obj, backend_obj)
   root_cert_obj = seolh_crypto.sign_cert(True, private_key_obj, csr_obj, certificate_lifetime_obj, hash_obj, config_obj, backend_obj)
   with open(config_obj.data['service_config']['root_certificate_file_name'], "wb") as f:
       f.write(root_cert_obj.public_bytes(serialization.Encoding.DER))
   with open(config_obj.data['service_config']['private_key_file'], "wb") as f:
       f.write(private_key_obj.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
   return

def generate_random_csr(config_obj, backend_obj):
   subject_obj = seolh_crypto.set_subject_name(config_obj, seolh_crypto.set_random_string())
   private_key_obj = seolh_crypto.set_private_key(config_obj, backend_obj)
   hash_obj = seolh_crypto.set_hash_name(config_obj)
   certificate_lifetime_obj = seolh_crypto.set_certificate_lifetime(config_obj)
   csr_obj = seolh_crypto.set_csr(private_key_obj, subject_obj, hash_obj, backend_obj)
   csr_txt = csr_obj.public_bytes(serialization.Encoding.PEM)
   return csr_txt

def process_csr(csr_text, config_obj, backend_obj):
   csr_obj = seolh_crypto.pem_decode_csr(str.encode(csr_text), backend_obj)
   private_key_obj = seolh_crypto.set_private_key(config_obj, backend_obj)
   hash_obj = seolh_crypto.set_hash_name(config_obj)
   certificate_lifetime_obj = seolh_crypto.set_certificate_lifetime(config_obj)
   client_cert = seolh_crypto.sign_cert(False, private_key_obj, csr_obj, certificate_lifetime_obj, hash_obj, config_obj, backend_obj)
   cert_txt = client_cert.public_bytes(serialization.Encoding.PEM).decode(encoding="utf-8", errors="strict")
   return cert_txt
