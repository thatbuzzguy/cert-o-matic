import yaml

def save(certificate_obj):
   temp_data = {
   'ca_config' : {
   #'app_version' : config_data['ca_config']['app_version'],
   'config_file' : config_data['ca_config']['config_file'],
   'backend' : config_data['ca_config']['backend'],  
   'common_name' : config_data['ca_config']['common_name'],
   'issuer_name' : config_data['ca_config']['issuer_name'],
   'subject_alternate_names' : config_data['ca_config']['subject_alternate_names'],
   'email_address' : config_data['ca_config']['email_address'],
   'organization' : config_data['ca_config']['organization'],
   'organizational_unit' : config_data['ca_config']['organizational_unit'],
   'city_or_locality' : config_data['ca_config']['city_or_locality'],
   'state_or_province' : config_data['ca_config']['state_or_province'],
   'country_name' : config_data['ca_config']['country_name'],
   'algorithm_name' : config_data['ca_config']['algorithm_name'],
   'hash_name' : config_data['ca_config']['hash_name'],
   'certificate_lifetime_in_days' : config_data['ca_config']['certificate_lifetime_in_days'],
   'private_key_file' : config_data['ca_config']['private_key_file'],
   'private_key_format' : config_data['ca_config']['private_key_format'],
   'private_key_password' : config_data['ca_config']['private_key_password'],
   'root_certificate_file_name' : config_data['ca_config']['root_certificate_file_name'],
   'root_certificate_format' : config_data['ca_config']['root_certificate_format'],
   'fqdn' : config_data['ca_config']['fqdn'],
   'ip_address' : config_data['ca_config']['ip_address'],
   'database' : config_data['ca_config']['database'],
   'port_number' : config_data['ca_config']['port_number'],
   'auth_psk' : config_data['ca_config']['auth_psk'],
   'email_address' : config_data['ca_config']['email_address'],
   'organization' : config_data['ca_config']['organization'],
   'organizational_unit' : config_data['ca_config']['organizational_unit'],
   'city_or_locality' : config_data['ca_config']['city_or_locality'],
   'state_or_province' : config_data['ca_config']['state_or_province'],
   'country_name' : config_data['ca_config']['country_name'],
   'algorithm_name' : config_data['ca_config']['algorithm_name'],
   'hash_name' : config_data['ca_config']['hash_name'],
   'certificate_lifetime_in_days' : config_data['ca_config']['certificate_lifetime_in_days']},
   'client_config' : {
   'email_address' : config_data['client_config']['email_address'],
   'organization' : config_data['client_config']['organization'],
   'organizational_unit' : config_data['client_config']['organizational_unit'],
   'city_or_locality' : config_data['client_config']['city_or_locality'],
   'state_or_province' : config_data['client_config']['state_or_province'],
   'country_name' : config_data['client_config']['country_name'],
   'algorithm_name' : config_data['client_config']['algorithm_name'],
   'hash_name' : config_data['client_config']['hash_name'],
   'certificate_lifetime_in_days' : config_data['client_config']['hash_name']}}
   
   with open("certomat.yaml", "w") as stream:
     stream.write(yaml.dump(temp_data, default_flow_style=False))
   return

def load(certificate_obj):

   with open("certomat.yaml", "r") as stream:
      temp_data = yaml.load(stream)

   #certificate_obj.config_data[['ca_config']['app_version'] = app_version
   certificate_obj.config_data[['ca_config']['config_file'] = temp_data['ca_config']['config_file']
   certificate_obj.config_data[['ca_config']['backend'] = temp_data['ca_config']['backend']
   certificate_obj.config_data[['ca_config']['common_name'] = temp_data['ca_config']['common_name']
   certificate_obj.config_data[['ca_config']['issuer_name'] = temp_data['ca_config']['issuer_name']
   certificate_obj.config_data[['ca_config']['subject_alternate_names'] = temp_data['ca_config']['subject_alternate_names']
   certificate_obj.config_data[['ca_config']['email_address'] = temp_data['ca_config']['email_address']
   certificate_obj.config_data[['ca_config']['organization'] = temp_data['ca_config']['organization']
   certificate_obj.config_data[['ca_config']['organizational_unit'] = temp_data['ca_config']['organizational_unit']
   certificate_obj.config_data[['ca_config']['city_or_locality'] = temp_data['ca_config']['city_or_locality']
   certificate_obj.config_data[['ca_config']['state_or_province'] = temp_data['ca_config']['state_or_province']
   certificate_obj.config_data[['ca_config']['country_name'] = temp_data['ca_config']['country_name']
   certificate_obj.config_data[['ca_config']['algorithm_name'] = temp_data['ca_config']['algorithm_name']
   certificate_obj.config_data[['ca_config']['hash_name'] = temp_data['ca_config']['hash_name']
   certificate_obj.config_data[['ca_config']['certificate_lifetime_in_days'] = temp_data['ca_config']['certificate_lifetime_in_days']
   certificate_obj.config_data[['ca_config']['private_key_file'] = temp_data['ca_config']['private_key_file']
   certificate_obj.config_data[['ca_config']['private_key_format'] = temp_data['ca_config']['private_key_format']
   certificate_obj.config_data[['ca_config']['private_key_password'] = temp_data['ca_config']['private_key_password']
   certificate_obj.config_data[['ca_config']['root_certificate_file_name'] = temp_data['ca_config']['root_certificate_file_name']
   certificate_obj.config_data[['ca_config']['root_certificate_format'] = temp_data['ca_config']['root_certificate_format']
   certificate_obj.config_data[['ca_config']['fqdn'] = temp_data['ca_config']['fqdn']
   certificate_obj.config_data[['ca_config']['ip_address'] = temp_data['ca_config']['ip_address']
   certificate_obj.config_data[['ca_config']['database'] = temp_data['ca_config']['database']
   certificate_obj.config_data[['ca_config']['port_number'] = temp_data['ca_config']['port_number']
   certificate_obj.config_data[['ca_config']['auth_psk'] = temp_data['ca_config']['auth_psk']
   certificate_obj.config_data[['client_config']['email_address'] = temp_data['client_config']['email_address']
   certificate_obj.config_data[['client_config']['organization'] = temp_data['client_config']['organization']
   certificate_obj.config_data[['client_config']['organizational_unit'] = temp_data['client_config']['organizational_unit']
   certificate_obj.config_data[['client_config']['city_or_locality'] = temp_data['client_config']['city_or_locality']
   certificate_obj.config_data[['client_config']['state_or_province'] = temp_data['client_config']['state_or_province']
   certificate_obj.config_data[['client_config']['country_name'] = temp_data['client_config']['country_name']
   certificate_obj.config_data[['client_config']['algorithm_name'] = temp_data['client_config']['algorithm_name']
   certificate_obj.config_data[['client_config']['hash_name'] = temp_data['client_config']['hash_name']
   certificate_obj.config_data[['client_config']['certificate_lifetime_in_days'] = temp_data['client_config']['certificate_lifetime_in_days']
   return(config_data)

def default(certificate_obj):
   #certificate_obj.config_data[['ca_config']['app_version'] = app_version
   certificate_obj.config_data[['ca_config']['config_file'] = 'certomat.yaml'
   certificate_obj.config_data[['ca_config']['backend'] = 'default_backend' 
   certificate_obj.config_data[['ca_config']['common_name'] = 'certomatic test ca'
   certificate_obj.config_data[['ca_config']['issuer_name'] = 'certomatic cross ca'
   certificate_obj.config_data[['ca_config']['subject_alternate_names'] = 'localhost'
   certificate_obj.config_data[['ca_config']['email_address'] = 'root@localhost'
   certificate_obj.config_data[['ca_config']['organization'] = 'Flying Circus'
   certificate_obj.config_data[['ca_config']['organizational_unit'] = 'Elephant Wrangler Union'
   certificate_obj.config_data[['ca_config']['city_or_locality'] = 'Pullman'
   certificate_obj.config_data[['ca_config']['state_or_province'] = 'WA'
   certificate_obj.config_data[['ca_config']['country_name'] = 'US'
   certificate_obj.config_data[['ca_config']['algorithm_name'] = 'secp256r1'
   certificate_obj.config_data[['ca_config']['hash_name'] = 'sha512'
   certificate_obj.config_data[['ca_config']['certificate_lifetime_in_days'] = 30
   certificate_obj.config_data[['ca_config']['private_key_file'] = 'root_private_key.der'
   certificate_obj.config_data[['ca_config']['private_key_format'] = 'der'
   certificate_obj.config_data[['ca_config']['private_key_password'] = None
   certificate_obj.config_data[['ca_config']['root_certificate_file_name'] = 'root_cert.der'
   certificate_obj.config_data[['ca_config']['root_certificate_format'] = 'der'
   certificate_obj.config_data[['ca_config']['fqdn'] = 'localhost'
   certificate_obj.config_data[['ca_config']['ip_address'] = '127.0.0.1'
   certificate_obj.config_data[['ca_config']['database'] = 'ca_database.txt'
   certificate_obj.config_data[['ca_config']['port_number'] = 80
   certificate_obj.config_data[['ca_config']['auth_psk'] = None
   certificate_obj.config_data[['client_config']['email_address'] = 'user@localhost'
   certificate_obj.config_data[['client_config']['organization'] = 'Flying Circus'
   certificate_obj.config_data[['client_config']['organizational_unit'] = 'Elephant Wrangler Union'
   certificate_obj.config_data[['client_config']['city_or_locality'] = 'Pullman'
   certificate_obj.config_data[['client_config']['state_or_province'] = 'WA'
   certificate_obj.config_data[['client_config']['country_name'] = 'US'
   certificate_obj.config_data[['client_config']['algorithm_name'] = 'secp256r1'
   certificate_obj.config_data[['client_config']['hash_name'] = 'sha512'
   certificate_obj.config_data[['client_config']['certificate_lifetime_in_days'] = 1 
   return config_data
