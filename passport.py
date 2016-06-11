from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, request, jsonify, Response

appversion = "passport .001-early"

def genrsakey(bitlength):
    key = rsa.generate_private_key(public_exponent=65537,key_size=bitlength,backend=default_backend())
    return(key)

def exportkey(key):
    pem = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    text = pem.decode('ascii')
    return(text)

def gencsr(key, subject):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject)).sign(key, hashes.SHA256(), default_backend())
    return(csr)

def exportcsr(csr):
    pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
    return(pem)


app = Flask(__name__)

@app.route('/')
def version():
    
    return(appversion)


@app.route('/test')
def test():
    key = genrsakey(4096)
    

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        ])
    csr = gencsr(key, subject)
           
    resp = Response(response=exportcsr(csr), status=200, mimetype="application/json")
    
    return(resp)
