# -*- coding: utf8 -*-
import os
import typer
import ipaddress
import datetime
import json
import csv
import xml.etree.ElementTree as ET
import xml.dom.minidom
import requests
import re
requests.packages.urllib3.disable_warnings()
from click import progressbar
current_date = datetime.datetime.now().strftime("%Y%m%d")

def pretty_xml(xml_string):
    parse_xml = xml.dom.minidom.parseString(xml_string)
    pretty_xml = parse_xml.toprettyxml()
    
    return pretty_xml

def paloalto_api(device_ip, parameter):
    try:
        response = requests.get(f"https://{device_ip}/api/", params=parameter, verify=False)
        return response
    
    except ValueError:
        exit('Invalid parameter')

def get_api_key(device_ip, username, password):
    keygen_parameter = (
        ('type', 'keygen'),
        ('user', username),
        ('password', password)
    )
    
    response = paloalto_api(device_ip, keygen_parameter)
    key_value = ET.fromstring(response.text).find('./result/key')
    api_key = key_value.text
    
    return api_key

def get_config(device_ip, username, password):
    api_key = get_api_key(device_ip, username, password)
    export_parameter = (
        ('type', 'export'),
        ('category', 'configuration'),
        ('key', api_key)
    )
    
    config_xml = paloalto_api(device_ip, export_parameter).text
    
    return config_xml

def list_to_string(list_data):
    return ','.join(str(s) for s in list_data)

def get_member(entry):
    try:
        result = [ member.text for member in entry ]
    except:
        result = []
    
    return result

def export_security_rules_from_config(device_ip, username, password, hostname):
    save_file = f'./{current_date}-{hostname}-security-rules.csv'
    
    tree = ET.fromstring(get_config(device_ip, username, password))
    rulebase = tree.findall('./devices/entry/vsys/entry/rulebase/security/rules/entry')
    security_rules = []
    sequence_number = 1
    
    for rule in rulebase:
        rule_objects = [hostname, sequence_number]
        
        rule_name = str(rule.attrib.get('name'))
        disabled = get_member(rule.findall('./disabled'))
        if not disabled:
            disabled = 'no'
            
        action = get_member(rule.findall('./action'))
        tag = get_member(rule.findall('./tag/member'))
        from_list = get_member(rule.findall('./from/member'))
        source_list = get_member(rule.findall('./source/member'))
        source_user_list = get_member(rule.findall('./source-user/member'))
        to_list = get_member(rule.findall('./to/member'))
        destination_list = get_member(rule.findall('./destination/member'))
        service_list = get_member(rule.findall('./service/member'))
        application_list = get_member(rule.findall('./application/member'))
        description_list = get_member(rule.findall('./description'))
        description_list = [ i.replace('\n',' ') if type(i) is str else i for i in description_list ]
        hip_profiles = get_member(rule.findall('./hip-profiles'))
        category = get_member(rule.findall('./category'))
        log_profile = get_member(rule.findall('./log-setting'))
        
        rule_objects.append(rule_name)
        if isinstance(disabled, list):
            rule_objects.append(list_to_string(disabled))
        else:
            rule_objects.append(disabled)
        
        rule_objects.append(list_to_string(action))
        rule_objects.append(list_to_string(tag))
        rule_objects.append(list_to_string(from_list))
        rule_objects.append(list_to_string(source_list))
        rule_objects.append(list_to_string(source_user_list))
        rule_objects.append(list_to_string(to_list))
        rule_objects.append(list_to_string(destination_list))
        rule_objects.append(list_to_string(service_list))
        rule_objects.append(list_to_string(application_list))
        rule_objects.append(list_to_string(hip_profiles))
        rule_objects.append(list_to_string(category))
        rule_objects.append(list_to_string(description_list))
        rule_objects.append(list_to_string(log_profile))
        
        security_rules.append(rule_objects)
        sequence_number += 1
        
    with open(save_file, mode='w', newline='', encoding='utf-8-sig') as result:
        wr = csv.writer(result)
        wr.writerow(['Hostname', 'Seq', 'Rulename', 'Disabled', 'Action', 'Tag', 'From', 'Source', 'User', 'To', 'Destination', 'Service', 'Application', 'Profiles', 'Category', 'Description', 'Log-Profile'])
        
        for rule in security_rules:
            wr.writerow(rule)