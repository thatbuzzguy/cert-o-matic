from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

import certomat_main

def init(config_data):
   subject_obj = certomat_main.set_subject_name(config_data['common_name'])
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

