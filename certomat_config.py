import yaml

def save(config_data):
   tempdata = {
   'app_version' : config_data['app_version'],
   'config_file' : config_data['config_file'],
   'backend' : config_data['backend'], 
   'initialized' : config_data['initialized'], 
   'common_name' : config_data['common_name'],
   'subject_alternate_names' : config_data['subject_alternate_names'],
   'serial_number' : config_data['serial_number'],
   'email_address' : config_data['email_address'],
   'organization' : config_data['organization'],
   'organizational_unit' : config_data['organizational_unit'],
   'city_or_locality' : config_data['city_or_locality'],
   'state_or_province' : config_data['state_or_province'],
   'country_name' : config_data['country_name'],
   'algorithm_name' : config_data['algorithm_name'],
   'hash_name' : config_data['hash_name'],
   'certificate_lifetime_in_days' : config_data['certificate_lifetime_in_days'],
   'private_key_file' : config_data['private_key_file'],
   'private_key_format' : config_data['private_key_format'],
   'private_key_password' : config_data['private_key_password'],
   'root_certificate_file_name' : config_data['root_certificate_file_name'],
   'root_certificate_format' : config_data['root_certificate_format'],
   'fqdn' : config_data['fqdn'],
   'ip_address' : config_data['ip_address'],
   'database' : config_data['database'],
   'port_number' : config_data['port_number'],
   'auth_psk' : config_data['auth_psk']}
   with open("certomat.yaml", "w") as stream:
     stream.write(yaml.dump(tempdata, default_flow_style=False))
   return

def load():
   config_data = {}
   temp_data = {}

   with open("certomat.yaml", "r") as stream:
      temp_data = yaml.load(stream)

   config_data['app_version'] = temp_data['app_version']
   config_data['config_file'] = temp_data['config_file']
   config_data['backend'] = temp_data['backend'] 
   config_data['initialized'] = temp_data['initialized'] 
   config_data['common_name'] = temp_data['common_name']
   config_data['subject_alternate_names'] = temp_data['subject_alternate_names']
   config_data['serial_number'] = int(temp_data['serial_number'])
   config_data['email_address'] = temp_data['email_address']
   config_data['organization'] = temp_data['organization']
   config_data['organizational_unit'] = temp_data['organizational_unit']
   config_data['city_or_locality'] = temp_data['city_or_locality']
   config_data['state_or_province'] = temp_data['state_or_province']
   config_data['country_name'] = temp_data['country_name']
   config_data['algorithm_name'] = temp_data['algorithm_name']
   config_data['hash_name'] = temp_data['hash_name']
   config_data['certificate_lifetime_in_days'] = temp_data['certificate_lifetime_in_days']
   config_data['private_key_file'] = temp_data['private_key_file']
   config_data['private_key_format'] = temp_data['private_key_format']
   config_data['private_key_password'] = temp_data['private_key_password']
   config_data['root_certificate_file_name'] = temp_data['root_certificate_file_name']
   config_data['root_certificate_format'] = temp_data['root_certificate_format']
   config_data['fqdn'] = temp_data['fqdn']
   config_data['ip_address'] = temp_data['ip_address']
   config_data['database'] = temp_data['database']
   config_data['port_number'] = temp_data['port_number']
   config_data['auth_psk'] = temp_data['auth_psk']      
   return config_data

def default(app_version, serial_number, config_data):
   config_data['app_version'] = app_version
   config_data['config_file'] = 'certomat.yaml'
   config_data['backend'] = 'default_backend' 
   config_data['initialized'] = True
   config_data['common_name'] = 'certomatic test ca'
   config_data['subject_alternate_names'] = 'localhost'
   config_data['serial_number'] = serial_number
   config_data['email_address'] = 'root@localhost'
   config_data['organization'] = 'Flying Circus'
   config_data['organizational_unit'] = 'Elephant Wrangler Union'
   config_data['city_or_locality'] = 'Pullman'
   config_data['state_or_province'] = 'WA'
   config_data['country_name'] = 'US'
   config_data['algorithm_name'] = 'rsa4096'
   config_data['hash_name'] = 'sha512'
   config_data['certificate_lifetime_in_days'] = 30
   config_data['private_key_file'] = 'root_private_key.der'
   config_data['private_key_format'] = 'der'
   config_data['private_key_password'] = None
   config_data['root_certificate_file_name'] = 'root_cert.der'
   config_data['root_certificate_format'] = 'der'
   config_data['fqdn'] = 'localhost'
   config_data['ip_address'] = '127.0.0.1'
   config_data['database'] = None
   config_data['port_number'] = 80
   config_data['auth_psk'] = None  
   return config_data
