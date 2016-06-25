from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Flask, request, jsonify, Response, render_template 
import json
import os.path
import certomat_config
import certomat_core

global private_key_obj
global app_version

class ca:
   def __init__(self, config_data, serial_number):
      self.config_data = config_data
      self.config_data['serial_number'] = certomat_core.set_serial_number()

class certificate:
   def __init__(self, config_data, serial_number):
      self.config_data = config_data
      self.config_data['serial_number'] = certomat_core.set_serial_number()

def set_backend(config_data):
   backend = config_data['backend']
   if backend == 'default_backend':
      backend_obj=default_backend()
   else:
      backend_obj=default_backend()
   return backend_obj

def file_exists(file_name):
   exists = os.path.isfile(file_name)
   return exists

app_version = '.0000004pre-alpaca'
config_data = certomat_config.load()
backend_obj = set_backend(config_data)

print(config_data.get('app_version', ''))

if file_exists(config_data['private_key_file']):
   with open(config_data['private_key_file'], "rb") as key_file:
      private_key_obj = serialization.load_pem_private_key(key_file.read(), password=None, backend=backend_obj)
else:
   certomat_ca.init(config_data)
   
app = Flask(__name__)

@app.route('/')
def root():
   resp = Response(response='<html><a href=\"/version\">Version</a><p>' + \
                   '<a href=\"/initalize\">initalize</a><p>' + \
                   '<a href=\"/config-save\">config-save</a><p>' + \
                   '<a href=\"/config-load\">config-load</a><p>' + \
                   '<a href=\"/config-default\">config-default</a>' \
                   , status=200)
   return(resp)

@app.route('/version')
def version():
   version = config_data.get('app_version', '')
   return version 

@app.route('/initalize')
def initalize():
   certomat_core.init(config_data, backend_obj)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-save')
def config_save():
   certomat_config.save(config_data)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-load')
def config_load():
   certomat_config.load()
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-default')
def config_default():
   certomat_config.default(app_version, certomat_core.set_serial_number(), config_data)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/test')
def test():
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/csr')
def csr():
    return render_template('form_submit.html')

@app.route('/certificate', methods=['POST'])
def certificate():
    csr=request.form['csr']
    return render_template('form_action.html', csr=csr)

if __name__ == '__main__':
   app.run(host=config_data['ip_address'], port=config_data['port_number'])
