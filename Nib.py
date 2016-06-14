from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import uuid
import yaml

appversion = "Nib .003"


def gen_rsa_private_key(bit_length):
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=bit_length,backend=default_backend())
    return(private_key)

def gen_rsa_public_key(private_key):
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
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject_name).sign(private_key, hashes.SHA256(), default_backend())
    return(csr)

def sign_cert(self_signed, private_key, csr, serial_number, cert_lifetime, ca_issuer_name, hash_type):
   builder = x509.CertificateBuilder()
   builder = builder.issuer_name(ca_issuer_name)
   builder = builder.not_valid_before(datetime.datetime.utcnow())

   builder = builder.not_valid_after(datetime.datetime.utcnow() + cert_lifetime)
   #builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False, )
   builder = builder.serial_number(int(uuid.uuid4()))

   if self_signed == True:
      builder = builder.public_key(private_key.public_key())
      builder = builder.subject_name(ca_issuer_name)
      builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True,)

   else:
      builder = builder.public_key(csr.public_key())
      builder = builder.subject_name(csr.subject)
      builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,)

   builder = builder.sign(private_key, hash_type, default_backend())

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

subject_name = build_subject_name("test")
private_key = gen_rsa_private_key(4096)
private_key2 = gen_rsa_private_key(2048)

csr = gen_csr(private_key2, subject_name)
serial_number = int(uuid.uuid4())
cert_lifetime = datetime.timedelta(1, 0, 0)
ca_issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test Root 1'),])
hash_type = hashes.SHA256()
root_cert = sign_cert(True, private_key, csr, serial_number, cert_lifetime, ca_issuer_name, hash_type)
client_cert = sign_cert(False, private_key, csr, serial_number, cert_lifetime, ca_issuer_name, hash_type)

with open("root_cert.der", "wb") as f:
    f.write(root_cert.public_bytes(serialization.Encoding.DER))

with open("client_cert.der", "wb") as f:
    f.write(client_cert.public_bytes(serialization.Encoding.DER))


