import yaml
import certomat_crypto

def save(config_obj):
   temp_data = {
   'global_config' : {
   'backend' : config_obj.data['global_config']['backend'],  
   'root_certificate_file_name' : config_obj.data['global_config']['root_certificate_file_name'],
   'root_certificate_format' : config_obj.data['global_config']['root_certificate_format'],
   'fqdn' : config_obj.data['global_config']['fqdn'],
   'ip_address' : config_obj.data['global_config']['ip_address'],
   'port_number' : config_obj.data['global_config']['port_number'],
   'auth_psk' : config_obj.data['global_config']['auth_psk']},
   'certificate_config' : {
   'self_signed' : temp_data['self_signed'],
   'email_address' : config_obj.data['certificate_config']['email_address'],
   'organization' : config_obj.data['certificate_config']['organization'],
   'organizational_unit' : config_obj.data['certificate_config']['organizational_unit'],
   'city_or_locality' : config_obj.data['certificate_config']['city_or_locality'],
   'state_or_province' : config_obj.data['certificate_config']['state_or_province'],
   'country_name' : config_obj.data['certificate_config']['country_name'],
   'algorithm_name' : config_obj.data['certificate_config']['algorithm_name'],
   'hash_name' : config_obj.data['certificate_config']['hash_name'],
   'certificate_lifetime_in_days' : config_obj.data['certificate_config']['certificate_lifetime_in_days'],
   'serial_number' : config_obj.data['certificate_config']['serial_number'],
   'fqdn' : config_obj.data['certificate_config']['fqdn']}}
   with open("certomat.yaml", "w") as stream:
     stream.write(yaml.dump(temp_data, default_flow_style=False))
   return

def load(config_obj):
   with open("certomat.yaml", "r") as stream:
      temp_data = yaml.load(stream)
   config_obj.data['global_config']['backend'] = temp_data['global_config']['backend']
   config_obj.data['global_config']['root_certificate_file_name'] = temp_data['global_config']['root_certificate_file_name']
   config_obj.data['global_config']['root_certificate_format'] = temp_data['global_config']['root_certificate_format']
   config_obj.data['global_config']['fqdn'] = temp_data['global_config']['fqdn']
   config_obj.data['global_config']['port_number'] = temp_data['global_config']['port_number']
   config_obj.data['global_config']['auth_psk'] = temp_data['global_config']['auth_psk']
   config_obj.data['certificate_config']['self_signed'] = temp_data['certificate_config']['self_signed']
   config_obj.data['certificate_config']['email_address'] = temp_data['certificate_config']['email_address']
   config_obj.data['certificate_config']['organization'] = temp_data['certificate_config']['organization']
   config_obj.data['certificate_config']['organizational_unit'] = temp_data['certificate_config']['organizational_unit']
   config_obj.data['certificate_config']['city_or_locality'] = temp_data['certificate_config']['city_or_locality']
   config_obj.data['certificate_config']['state_or_province'] = temp_data['certificate_config']['state_or_province']
   config_obj.data['certificate_config']['country_name'] = temp_data['certificate_config']['country_name']
   config_obj.data['certificate_config']['algorithm_name'] = temp_data['certificate_config']['algorithm_name']
   config_obj.data['certificate_config']['hash_name'] = temp_data['certificate_config']['hash_name']
   config_obj.data['certificate_config']['certificate_lifetime_in_days'] = temp_data['certificate_config']['certificate_lifetime_in_days']
   config_obj.data['certificate_config']['serial_number'] = temp_data['certificate_config']['serial_number']
   config_obj.data['certificate_config']['fqdn'] = temp_data['certificate_config']['fqdn']
   return(config_obj)

def default(config_obj):
   config_obj.data['global_config']['backend'] = 'default_backend' 
   config_obj.data['global_config']['root_certificate_file_name'] = 'root_cert.der'
   config_obj.data['global_config']['root_certificate_format'] = 'der'
   config_obj.data['global_config']['fqdn'] = 'localhost'
   config_obj.data['global_config']['port_number'] = 80
   config_obj.data['global_config']['auth_psk'] = None
   config_obj.data['certificate_config']['self_signed'] = True
   config_obj.data['certificate_config']['email_address'] = 'user@localhost'
   config_obj.data['certificate_config']['organization'] = 'Flying Circus'
   config_obj.data['certificate_config']['organizational_unit'] = 'Elephant Wrangler Union'
   config_obj.data['certificate_config']['city_or_locality'] = 'Pullman'
   config_obj.data['certificate_config']['state_or_province'] = 'WA'
   config_obj.data['certificate_config']['country_name'] = 'US'
   config_obj.data['certificate_config']['algorithm_name'] = 'secp256r1'
   config_obj.data['certificate_config']['hash_name'] = 'sha512'
   config_obj.data['certificate_config']['certificate_lifetime_in_days'] = 1
   config_obj.data['certificate_config']['serial_number'] = certomat_crypto.set_serial_number()
   config_obj.data['certificate_config']['fqdn'] = 'test.local'
   return config_obj
