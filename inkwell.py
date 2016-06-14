from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import uuid
import yaml

appversion = "Inkwell .001-early"
one_day = datetime.timedelta(1, 0, 0)

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

def sign_cert(self_signed, private_key, csr):
   if self_signed == True:
      subject = issuer = x509.Name([
      x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
      x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
      x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
      ])

      builder = x509.CertificateBuilder()
      builder = builder.subject_name(subject)
      builder = builder.issuer_name(issuer)
      builder = builder.public_key(private_key.public_key())
      builder = builder.not_valid_before(datetime.datetime.utcnow())
      builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
      builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False, )
      builder = builder.sign(private_key, hashes.SHA256(), default_backend())

   else:
      builder = x509.CertificateBuilder()
      builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'Test Root 1'),]))
      builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'Passport Development Lab'),]))
      builder = builder.not_valid_before(datetime.datetime.today())
      builder = builder.not_valid_after(datetime.datetime.today() + one_day)
      builder = builder.serial_number(int(uuid.uuid4()))
      builder = builder.public_key(public_key)
      builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True,)
      certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(),backend=default_backend())

   return certificate


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
private_key = gen_rsa_private_key(2048)
public_key = gen_rsa_public_key(private_key)
csr = gen_csr(private_key, subject_name)

#rootcert = gen_root_cert(private_key, public_key)

