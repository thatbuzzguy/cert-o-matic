from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Flask, request, jsonify, Response, render_template, redirect, url_for
import json
import os.path
import certomat_config
import certomat_core
import datetime

class certificate():
   def __init__(self, app_version):
      self.app_version = app_version
      self.serial_number = certomat_core.set_serial_number()
      self.self_signed = bool
      self.config_data = {}
      self.config_data['ca_config'] = {}
      self.config_data['client_config'] = {}

def set_backend(config_data):
   backend = config_data['ca_config']['backend']
   if backend == 'default_backend':
      backend_obj=default_backend()
   else:
      backend_obj=default_backend()
   return backend_obj

def file_exists(file_name):
   exists = os.path.isfile(file_name)
   return exists

app_version = '.0010alpha'
ca_obj = certificate(app_version)
request_obj = certificate(app_version)
ca_obj = certomat_config.load(ca_obj)
backend_obj = set_backend(ca_obj.config_data)

if file_exists(ca_obj.config_data['ca_config']['private_key_file']):
   with open(ca_obj.config_data['ca_config']['private_key_file'], "rb") as key_file:
      private_key_obj = serialization.load_pem_private_key(key_file.read(), password=None, backend=backend_obj)
else:
   certomat_core.initalize(ca_obj, backend_obj)

with open("certomat.log", "a") as log:
   log.write('Certomat ' + app_version + ' startup ' + datetime.datetime.now().__str__() + '\n')

app = Flask(__name__)

@app.route('/')
def root():
   return redirect(url_for('help'))

@app.route('/help')
def help():
   resp = Response(response='<html><a href=\"/version\">version</a><p>' + \
   '<a href=\"/initalize\">initalize</a><p>' + \
   '<a href=\"/generate-request\">generate-request</a><p>' + \
   '<a href=\"/process-request\">process-request</a><p>' + \
   '<a href=\"/config-save\">config-save</a><p>' + \
   '<a href=\"/config-load\">config-load</a><p>' + \
   '<a href=\"/config-default\">config-default</a>' \
   , status=200)
   return(resp)

@app.route('/version')
def version():
   version = ca_obj.app_version
   return version 

@app.route('/initalize')
def initalize():
   certomat_core.initalize(ca_obj, backend_obj)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-save')
def config_save():
   certomat_config.save(ca_obj)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-load')
def config_load():
   certomat_config.load(ca_obj)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-default')
def config_default():
   certomat_config.default(ca_obj)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/generate-request')
def generate_request():
   req_text = certomat_core.generate_request(ca_obj, backend_obj)
   resp = Response(response=req_text, status=200, mimetype="application/json")
   return(resp)

@app.route('/process-request')
def process_request():
   cert_text = certomat_core.process_request(ca_obj, backend_obj)
   resp = Response(response=cert_text, status=200, mimetype="application/json")
   return(resp)

@app.route('/save-request')
def save_request():
   cert_text = certomat_core.save_request(backend_obj, request_obj)
   resp = Response(response=cert_text, status=200, mimetype="application/json")
   return(resp)

@app.route('/csr')
def csr():
    return render_template('form_submit.html')

@app.route('/certificate', methods=['POST'])
def certificate(config_data, serial_number):
    csr=request.form['csr']
    return render_template('form_action.html', csr=csr)

if __name__ == '__main__':
   app.run(host=ca_obj.config_data['ca_config']['ip_address'], port=ca_obj.config_data['ca_config']['port_number'])

