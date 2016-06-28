import yaml

def save(ca_obj):
   temp_data = {
   'ca_config' : {
   'config_file' : ca_obj.config_data['ca_config']['config_file'],
   'backend' : ca_obj.config_data['ca_config']['backend'],  
   'common_name' : ca_obj.config_data['ca_config']['common_name'],
   'issuer_name' : ca_obj.config_data['ca_config']['issuer_name'],
   'subject_alternate_names' : ca_obj.config_data['ca_config']['subject_alternate_names'],
   'email_address' : ca_obj.config_data['ca_config']['email_address'],
   'organization' : ca_obj.config_data['ca_config']['organization'],
   'organizational_unit' : ca_obj.config_data['ca_config']['organizational_unit'],
   'city_or_locality' : ca_obj.config_data['ca_config']['city_or_locality'],
   'state_or_province' : ca_obj.config_data['ca_config']['state_or_province'],
   'country_name' : ca_obj.config_data['ca_config']['country_name'],
   'algorithm_name' : ca_obj.config_data['ca_config']['algorithm_name'],
   'hash_name' : ca_obj.config_data['ca_config']['hash_name'],
   'certificate_lifetime_in_days' : ca_obj.config_data['ca_config']['certificate_lifetime_in_days'],
   'private_key_file' : ca_obj.config_data['ca_config']['private_key_file'],
   'private_key_format' : ca_obj.config_data['ca_config']['private_key_format'],
   'private_key_password' : ca_obj.config_data['ca_config']['private_key_password'],
   'root_certificate_file_name' : ca_obj.config_data['ca_config']['root_certificate_file_name'],
   'root_certificate_format' : ca_obj.config_data['ca_config']['root_certificate_format'],
   'fqdn' : ca_obj.config_data['ca_config']['fqdn'],
   'ip_address' : ca_obj.config_data['ca_config']['ip_address'],
   'database' : ca_obj.config_data['ca_config']['database'],
   'port_number' : ca_obj.config_data['ca_config']['port_number'],
   'auth_psk' : ca_obj.config_data['ca_config']['auth_psk'],
   'email_address' : ca_obj.config_data['ca_config']['email_address'],
   'organization' : ca_obj.config_data['ca_config']['organization'],
   'organizational_unit' : ca_obj.config_data['ca_config']['organizational_unit'],
   'city_or_locality' : ca_obj.config_data['ca_config']['city_or_locality'],
   'state_or_province' : ca_obj.config_data['ca_config']['state_or_province'],
   'country_name' : ca_obj.config_data['ca_config']['country_name'],
   'algorithm_name' : ca_obj.config_data['ca_config']['algorithm_name'],
   'hash_name' : ca_obj.config_data['ca_config']['hash_name'],
   'certificate_lifetime_in_days' : ca_obj.config_data['ca_config']['certificate_lifetime_in_days']},
   'client_config' : {
   'email_address' : ca_obj.config_data['client_config']['email_address'],
   'organization' : ca_obj.config_data['client_config']['organization'],
   'organizational_unit' : ca_obj.config_data['client_config']['organizational_unit'],
   'city_or_locality' : ca_obj.config_data['client_config']['city_or_locality'],
   'state_or_province' : ca_obj.config_data['client_config']['state_or_province'],
   'country_name' : ca_obj.config_data['client_config']['country_name'],
   'algorithm_name' : ca_obj.config_data['client_config']['algorithm_name'],
   'hash_name' : ca_obj.config_data['client_config']['hash_name'],
   'certificate_lifetime_in_days' : ca_obj.config_data['client_config']['hash_name']}}
   
   with open("certomat.yaml", "w") as stream:
     stream.write(yaml.dump(temp_data, default_flow_style=False))
   return

def load(ca_obj):

   with open("certomat.yaml", "r") as stream:
      temp_data = yaml.load(stream)
   ca_obj.config_data['ca_config']['config_file'] = temp_data['ca_config']['config_file']
   ca_obj.config_data['ca_config']['backend'] = temp_data['ca_config']['backend']
   ca_obj.config_data['ca_config']['common_name'] = temp_data['ca_config']['common_name']
   ca_obj.config_data['ca_config']['issuer_name'] = temp_data['ca_config']['issuer_name']
   ca_obj.config_data['ca_config']['subject_alternate_names'] = temp_data['ca_config']['subject_alternate_names']
   ca_obj.config_data['ca_config']['email_address'] = temp_data['ca_config']['email_address']
   ca_obj.config_data['ca_config']['organization'] = temp_data['ca_config']['organization']
   ca_obj.config_data['ca_config']['organizational_unit'] = temp_data['ca_config']['organizational_unit']
   ca_obj.config_data['ca_config']['city_or_locality'] = temp_data['ca_config']['city_or_locality']
   ca_obj.config_data['ca_config']['state_or_province'] = temp_data['ca_config']['state_or_province']
   ca_obj.config_data['ca_config']['country_name'] = temp_data['ca_config']['country_name']
   ca_obj.config_data['ca_config']['algorithm_name'] = temp_data['ca_config']['algorithm_name']
   ca_obj.config_data['ca_config']['hash_name'] = temp_data['ca_config']['hash_name']
   ca_obj.config_data['ca_config']['certificate_lifetime_in_days'] = temp_data['ca_config']['certificate_lifetime_in_days']
   ca_obj.config_data['ca_config']['private_key_file'] = temp_data['ca_config']['private_key_file']
   ca_obj.config_data['ca_config']['private_key_format'] = temp_data['ca_config']['private_key_format']
   ca_obj.config_data['ca_config']['private_key_password'] = temp_data['ca_config']['private_key_password']
   ca_obj.config_data['ca_config']['root_certificate_file_name'] = temp_data['ca_config']['root_certificate_file_name']
   ca_obj.config_data['ca_config']['root_certificate_format'] = temp_data['ca_config']['root_certificate_format']
   ca_obj.config_data['ca_config']['fqdn'] = temp_data['ca_config']['fqdn']
   ca_obj.config_data['ca_config']['ip_address'] = temp_data['ca_config']['ip_address']
   ca_obj.config_data['ca_config']['database'] = temp_data['ca_config']['database']
   ca_obj.config_data['ca_config']['port_number'] = temp_data['ca_config']['port_number']
   ca_obj.config_data['ca_config']['auth_psk'] = temp_data['ca_config']['auth_psk']
   ca_obj.config_data['client_config']['email_address'] = temp_data['client_config']['email_address']
   ca_obj.config_data['client_config']['organization'] = temp_data['client_config']['organization']
   ca_obj.config_data['client_config']['organizational_unit'] = temp_data['client_config']['organizational_unit']
   ca_obj.config_data['client_config']['city_or_locality'] = temp_data['client_config']['city_or_locality']
   ca_obj.config_data['client_config']['state_or_province'] = temp_data['client_config']['state_or_province']
   ca_obj.config_data['client_config']['country_name'] = temp_data['client_config']['country_name']
   ca_obj.config_data['client_config']['algorithm_name'] = temp_data['client_config']['algorithm_name']
   ca_obj.config_data['client_config']['hash_name'] = temp_data['client_config']['hash_name']
   ca_obj.config_data['client_config']['certificate_lifetime_in_days'] = temp_data['client_config']['certificate_lifetime_in_days']
   return(ca_obj)

def default(ca_obj):
   ca_obj.config_data['ca_config']['config_file'] = 'certomat.yaml'
   ca_obj.config_data['ca_config']['backend'] = 'default_backend' 
   ca_obj.config_data['ca_config']['common_name'] = 'certomatic test ca'
   ca_obj.config_data['ca_config']['issuer_name'] = 'certomatic cross ca'
   ca_obj.config_data['ca_config']['subject_alternate_names'] = 'localhost'
   ca_obj.config_data['ca_config']['email_address'] = 'root@localhost'
   ca_obj.config_data['ca_config']['organization'] = 'Flying Circus'
   ca_obj.config_data['ca_config']['organizational_unit'] = 'Elephant Wrangler Union'
   ca_obj.config_data['ca_config']['city_or_locality'] = 'Pullman'
   ca_obj.config_data['ca_config']['state_or_province'] = 'WA'
   ca_obj.config_data['ca_config']['country_name'] = 'US'
   ca_obj.config_data['ca_config']['algorithm_name'] = 'secp256r1'
   ca_obj.config_data['ca_config']['hash_name'] = 'sha512'
   ca_obj.config_data['ca_config']['certificate_lifetime_in_days'] = 30
   ca_obj.config_data['ca_config']['private_key_file'] = 'root_private_key.der'
   ca_obj.config_data['ca_config']['private_key_format'] = 'der'
   ca_obj.config_data['ca_config']['private_key_password'] = None
   ca_obj.config_data['ca_config']['root_certificate_file_name'] = 'root_cert.der'
   ca_obj.config_data['ca_config']['root_certificate_format'] = 'der'
   ca_obj.config_data['ca_config']['fqdn'] = 'localhost'
   ca_obj.config_data['ca_config']['ip_address'] = '127.0.0.1'
   ca_obj.config_data['ca_config']['database'] = 'ca_database.txt'
   ca_obj.config_data['ca_config']['port_number'] = 80
   ca_obj.config_data['ca_config']['auth_psk'] = None
   ca_obj.config_data['client_config']['email_address'] = 'user@localhost'
   ca_obj.config_data['client_config']['organization'] = 'Flying Circus'
   ca_obj.config_data['client_config']['organizational_unit'] = 'Elephant Wrangler Union'
   ca_obj.config_data['client_config']['city_or_locality'] = 'Pullman'
   ca_obj.config_data['client_config']['state_or_province'] = 'WA'
   ca_obj.config_data['client_config']['country_name'] = 'US'
   ca_obj.config_data['client_config']['algorithm_name'] = 'secp256r1'
   ca_obj.config_data['client_config']['hash_name'] = 'sha512'
   ca_obj.config_data['client_config']['certificate_lifetime_in_days'] = 1 
   return ca_obj
