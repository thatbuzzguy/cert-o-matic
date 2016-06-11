from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, request, jsonify, Response
import datetime
import uuid

appversion = "passport .001-early"
one_day = datetime.timedelta(1, 0, 0)

def gen_rsa_private_key(bit_length):
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=bit_length,backend=default_backend())
    return(private_key)

def gen_rsa_public_key(private_key):
    public_key = private_key.public_key()
    return(public_key)

def gen_cn(cn):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"West Sacramento"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Personal"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])
    return subject

def gen_csr(private_key, subject):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject)).sign(private_key, hashes.SHA256(), default_backend())
    return(csr)

def gen_cert(private_key, public_key, csr):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime(2018, 8, 2))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend())
    return(certificate)
        

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






app = Flask(__name__)

@app.route('/')
def version():
    return(appversion)

@app.route('/test')
def test():
    private_key = gen_rsa_private_key(2048)
    public_key = gen_rsa_public_key(private_key)
    
    subject = gen_cn('test')
    csr = gen_csr(private_key, subject)

    pem_csr = pem_encode_csr(csr)
    pem_public_key = pem_encode_public_key(public_key)
    
    resp = Response(response=pem_public_key, status=200, mimetype="application/json")
    return(resp)
