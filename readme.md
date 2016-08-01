Certomat is Certificate As a Service implementation written in Python.  Certomat is currently in an early stage of development, 
  so only a minimum of features have been implemented.  Here is an overview of the current state of the project.

-What Works-

-The Cryptography Python library with an OpenSSL backend are used to do all cryptographic work
-Certomat currently can self-sign a root certificate and sign child certificates
-Both EC and RSA based encryption algorithms are currently implemented 
-Adjustable key sizes are implemented
-Certomat is able to generate x509 style digital certificates that are suitable for SSL and TLS encryption
-Persistant settings are stored in YAML configuration files
-Certificates and keys are saved to DER encoded files for the time being
-Certomat is capable of signing Certificate Signing Requests CSRs 
-The Certomat client is capable of generating CSRs 
-Flask pages are available to demonstrate and test Certomat functionality 

-What Needs Work-

-The first API endpoint is not yet accepting CSR text which means that certificates have to be generated completely on the server 
  side or loaded from files
-Logging is very basic (startup and certificate issuing events are written to files)
-Certomat server should be able to accept certificate requests by message queue
-Certomat server should be able to accept certificate requests by file drop
-Certomat client should be able to request certificates by message queue
-Certomat client should be able to request certificates by file drop

Icons made by http://www.flaticon.com/authors/freepik from http://www.flaticon.com and is licensed by Creative Commons 3.0 BY
