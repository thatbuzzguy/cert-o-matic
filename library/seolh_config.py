import yaml
import seolh_crypto

def save(config_obj):
   temp_data = {
	
   'self_signed' : True, 
	
   'service_config' : {
   'config_file' : config_obj.data['service_config']['config_file'],
   'backend' : config_obj.data['service_config']['backend'],  
	'private_key_file' : config_obj.data['service_config']['private_key_file'],
   'private_key_format' : config_obj.data['service_config']['private_key_format'],
   'private_key_password' : config_obj.data['service_config']['private_key_password'],
   'root_certificate_file_name' : config_obj.data['service_config']['root_certificate_file_name'],
   'root_certificate_format' : config_obj.data['service_config']['root_certificate_format'],
   'fqdn' : config_obj.data['service_config']['fqdn'],
   'ip_address' : config_obj.data['service_config']['ip_address'],
   'database' : config_obj.data['service_config']['database'],
   'port_number' : config_obj.data['service_config']['port_number'],
   'auth_psk' : config_obj.data['service_config']['auth_psk'],
   'common_name' : config_obj.data['root_cert_config']['common_name'],
   'issuer_name' : config_obj.data['root_cert_config']['issuer_name'],
   'subject_alternate_names' : config_obj.data['root_cert_config']['subject_alternate_names'],
   'email_address' : config_obj.data['root_cert_config']['email_address'],
   'organization' : config_obj.data['root_cert_config']['organization'],
   'organizational_unit' : config_obj.data['root_cert_config']['organizational_unit'],
   'city_or_locality' : config_obj.data['root_cert_config']['city_or_locality'],
   'state_or_province' : config_obj.data['root_cert_config']['state_or_province'],
   'country_name' : config_obj.data['root_cert_config']['country_name'],
   'algorithm_name' : config_obj.data['root_cert_config']['algorithm_name'],
   'hash_name' : config_obj.data['root_cert_config']['hash_name'],
   'certificate_lifetime_in_days' : config_obj.data['root_cert_config']['certificate_lifetime_in_days'],
   'email_address' : config_obj.data['root_cert_config']['email_address'],
   'organization' : config_obj.data['root_cert_config']['organization'],
   'organizational_unit' : config_obj.data['root_cert_config']['organizational_unit'],
   'city_or_locality' : config_obj.data['root_cert_config']['city_or_locality'],
   'state_or_province' : config_obj.data['root_cert_config']['state_or_province'],
   'country_name' : config_obj.data['root_cert_config']['country_name'],
   'algorithm_name' : config_obj.data['root_cert_config']['algorithm_name'],
   'hash_name' : config_obj.data['root_cert_config']['hash_name'],
   'certificate_lifetime_in_days' : config_obj.data['root_cert_config']['certificate_lifetime_in_days']},
   'client_cert_config' : {
   'email_address' : config_obj.data['client_cert_config']['email_address'],
   'organization' : config_obj.data['client_cert_config']['organization'],
   'organizational_unit' : config_obj.data['client_cert_config']['organizational_unit'],
   'city_or_locality' : config_obj.data['client_cert_config']['city_or_locality'],
   'state_or_province' : config_obj.data['client_cert_config']['state_or_province'],
   'country_name' : config_obj.data['client_cert_config']['country_name'],
   'algorithm_name' : config_obj.data['client_cert_config']['algorithm_name'],
   'hash_name' : config_obj.data['client_cert_config']['hash_name'],
   'certificate_lifetime_in_days' : config_obj.data['client_cert_config']['certificate_lifetime_in_days']}}
   
   with open("seolh.yaml", "w") as stream:
     stream.write(yaml.dump(temp_data, default_flow_style=False))
     
   return

def load(config_obj):
   try:
      with open("seolh.yaml", "r") as stream:
         temp_data = yaml.load(stream)

      config_obj.data['self_signed'] = temp_data['self_signed']
		
		
      config_obj.data['service_config']['config_file'] = temp_data['service_config']['config_file']
      config_obj.data['service_config']['backend'] = temp_data['service_config']['backend']
      config_obj.data['service_config']['private_key_file'] = temp_data['service_config']['private_key_file']
      config_obj.data['service_config']['private_key_format'] = temp_data['service_config']['private_key_format']
      config_obj.data['service_config']['private_key_password'] = temp_data['service_config']['private_key_password']
      config_obj.data['service_config']['root_certificate_file_name'] = temp_data['service_config']['root_certificate_file_name']
      config_obj.data['service_config']['root_certificate_format'] = temp_data['service_config']['root_certificate_format']
      config_obj.data['service_config']['fqdn'] = temp_data['service_config']['fqdn']
      config_obj.data['service_config']['ip_address'] = temp_data['service_config']['ip_address']
      config_obj.data['service_config']['database'] = temp_data['service_config']['database']
      config_obj.data['service_config']['port_number'] = temp_data['service_config']['port_number']
      config_obj.data['service_config']['auth_psk'] = temp_data['service_config']['auth_psk']		
      config_obj.data['root_cert_config']['common_name'] = temp_data['root_cert_config']['common_name']
      config_obj.data['root_cert_config']['issuer_name'] = temp_data['root_cert_config']['issuer_name']
      config_obj.data['root_cert_config']['subject_alternate_names'] = temp_data['root_cert_config']['subject_alternate_names']
      config_obj.data['root_cert_config']['email_address'] = temp_data['root_cert_config']['email_address']
      config_obj.data['root_cert_config']['organization'] = temp_data['root_cert_config']['organization']
      config_obj.data['root_cert_config']['organizational_unit'] = temp_data['root_cert_config']['organizational_unit']
      config_obj.data['root_cert_config']['city_or_locality'] = temp_data['root_cert_config']['city_or_locality']
      config_obj.data['root_cert_config']['state_or_province'] = temp_data['root_cert_config']['state_or_province']
      config_obj.data['root_cert_config']['country_name'] = temp_data['root_cert_config']['country_name']
      config_obj.data['root_cert_config']['algorithm_name'] = temp_data['root_cert_config']['algorithm_name']
      config_obj.data['root_cert_config']['hash_name'] = temp_data['root_cert_config']['hash_name']
      config_obj.data['root_cert_config']['certificate_lifetime_in_days'] = temp_data['root_cert_config']['certificate_lifetime_in_days']
      config_obj.data['client_cert_config']['email_address'] = temp_data['client_cert_config']['email_address']
      config_obj.data['client_cert_config']['organization'] = temp_data['client_cert_config']['organization']
      config_obj.data['client_cert_config']['organizational_unit'] = temp_data['client_cert_config']['organizational_unit']
      config_obj.data['client_cert_config']['city_or_locality'] = temp_data['client_cert_config']['city_or_locality']
      config_obj.data['client_cert_config']['state_or_province'] = temp_data['client_cert_config']['state_or_province']
      config_obj.data['client_cert_config']['country_name'] = temp_data['client_cert_config']['country_name']
      config_obj.data['client_cert_config']['algorithm_name'] = temp_data['client_cert_config']['algorithm_name']
      config_obj.data['client_cert_config']['hash_name'] = temp_data['client_cert_config']['hash_name']
      config_obj.data['client_cert_config']['certificate_lifetime_in_days'] = temp_data['client_cert_config']['certificate_lifetime_in_days']

   except:
      default(config_obj)
      save(config_obj)

   return(config_obj)

def default(config_obj):
   config_obj.data['self_signed'] = seolh_crypto.set_serial_number()
   config_obj.data['self_signed'] = True
	
   config_obj.data['service_config']['config_file'] = 'seolh.yaml'
   config_obj.data['service_config']['backend'] = 'default_backend' 
   config_obj.data['service_config']['private_key_file'] = 'root_private_key.der'
   config_obj.data['service_config']['private_key_format'] = 'der'
   config_obj.data['service_config']['private_key_password'] = None
   config_obj.data['service_config']['root_certificate_file_name'] = 'root_cert.der'
   config_obj.data['service_config']['root_certificate_format'] = 'der'
   config_obj.data['service_config']['fqdn'] = 'localhost'
   config_obj.data['service_config']['ip_address'] = '127.0.0.1'
   config_obj.data['service_config']['database'] = 'ca.db'
   config_obj.data['service_config']['port_number'] = 80
   config_obj.data['service_config']['auth_psk'] = None
   config_obj.data['root_cert_config']['common_name'] = 'seolhic test ca'
   config_obj.data['root_cert_config']['issuer_name'] = 'seolhic test ca'
   config_obj.data['root_cert_config']['subject_alternate_names'] = 'localhost'
   config_obj.data['root_cert_config']['email_address'] = 'root@localhost'
   config_obj.data['root_cert_config']['organization'] = 'Flying Circus'
   config_obj.data['root_cert_config']['organizational_unit'] = 'Elephant Wrangler Union'
   config_obj.data['root_cert_config']['city_or_locality'] = 'Pullman'
   config_obj.data['root_cert_config']['state_or_province'] = 'WA'
   config_obj.data['root_cert_config']['country_name'] = 'US'
   config_obj.data['root_cert_config']['algorithm_name'] = 'secp256r1'
   config_obj.data['root_cert_config']['hash_name'] = 'sha512'
   config_obj.data['root_cert_config']['certificate_lifetime_in_days'] = 30
   config_obj.data['client_cert_config']['email_address'] = 'user@localhost'
   config_obj.data['client_cert_config']['organization'] = 'Flying Circus'
   config_obj.data['client_cert_config']['organizational_unit'] = 'Elephant Wrangler Union'
   config_obj.data['client_cert_config']['city_or_locality'] = 'Pullman'
   config_obj.data['client_cert_config']['state_or_province'] = 'WA'
   config_obj.data['client_cert_config']['country_name'] = 'US'
   config_obj.data['client_cert_config']['algorithm_name'] = 'secp256r1'
   config_obj.data['client_cert_config']['hash_name'] = 'sha512'
   config_obj.data['client_cert_config']['certificate_lifetime_in_days'] = 1
   return config_obj


