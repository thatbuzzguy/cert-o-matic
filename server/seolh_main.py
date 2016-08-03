from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Flask, request, jsonify, Response, render_template, redirect, url_for
import json
import os.path
import datetime
import sys

sys.path.insert(0, sys.path[0]+'..\\..\\library')

import seolh_config
import seolh_crypto

class config():
   def __init__(self):
      self.app_version = 'olive-v.02'
      #self.serial_number = int
      self.self_signed = bool
      self.data = {}
      self.data['global_config'] = {}
      self.data['certificate_config'] = {}

class request():
   def __init__(self):
      self.serial_number = int
      self.self_signed = bool
      self.data = {}

def set_backend(config_data):
   backend = config_data['global_config']['backend']
   if backend == 'default_backend':
      backend_obj=default_backend()
   else:
      backend_obj=default_backend()
   return backend_obj

def file_exists(file_name):
   exists = os.path.isfile(file_name)
   return exists

config_obj = config()
request_obj = config()
config_obj = seolh_config.load(config_obj)
backend_obj = set_backend(config_obj.data)

if file_exists(config_obj.data['global_config']['private_key_file']):
   with open(config_obj.data['global_config']['private_key_file'], "rb") as key_file:
      private_key_obj = serialization.load_pem_private_key(key_file.read(), password=None, backend=backend_obj)
else:
   seolh_crypto.initalize(config_obj, backend_obj)

with open("seolh.log", "a") as log:
   log.write('seolh ' + config_obj.app_version + ' startup ' + datetime.datetime.now().__str__() + '\n')

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
   version = config_obj.app_version
   return version 

@app.route('/initalize')
def initalize():
   seolh_crypto.initalize(config_obj, backend_obj)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-save')
def config_save():
   seolh_config.save(config_obj)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-load')
def config_load():
   seolh_config.load(config_obj)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/config-default')
def config_default():
   seolh_config.default(config_obj)
   resp = Response(response='ok', status=200, mimetype="application/json")
   return(resp)

@app.route('/generate-request')
def generate_request():
   req_text = seolh_crypto.generate_request(config_obj, backend_obj)
   resp = Response(response=req_text, status=200, mimetype="application/json")
   return(resp)

@app.route('/process-request')
def process_request():
   cert_text = seolh_crypto.process_request(config_obj, backend_obj)
   resp = Response(response=cert_text, status=200, mimetype="application/json")
   return(resp)

@app.route('/save-request')
def save_request():
   cert_text = seolh_crypto.save_request(config_obj, backend_obj)
   resp = Response(response=cert_text, status=200, mimetype="application/json")
   return(resp)

@app.route('/seolh/api/v1.0/request', methods=['POST'])
def api_post_request():
   if not request.json or not 'csr' in request.json:
      abort(400)
   
   request = {
      'csr': request.json['csr']
   }

   

   return

# jsonify({'tasks': tasks})


@app.route('/csr')
def csr():
    return render_template('form_submit.html')

@app.route('/certificate', methods=['POST'])
def certificate(config_data, serial_number):
    csr=request.form['csr']
    return render_template('form_action.html', csr=csr)

if __name__ == '__main__':
   app.run(host=config_obj.data['global_config']['ip_address'], port=config_obj.data['global_config']['port_number'])

