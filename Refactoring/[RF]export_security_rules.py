import csv
import datetime
import json
import os
import re
import xml.dom.minidom
import xml.etree.ElementTree as ET

import ipaddress
import requests
import typer

requests.packages.urllib3.disable_warnings()

current_date = datetime.datetime.now().strftime("%Y%m%d")


def pretty_xml(xml_string):
    parse_xml = xml.dom.minidom.parseString(xml_string)
    pretty_xml = parse_xml.toprettyxml()
    return pretty_xml


def paloalto_api(device_ip: str, parameter: dict) -> requests.Response:
    response = requests.get(f"https://{device_ip}/api/", params=parameter, verify=False)
    response.raise_for_status()
    return response


def get_api_key(device_ip: str, username: str, password: str) -> str:
    keygen_parameter = {
        'type': 'keygen',
        'user': username,
        'password': password
    }

    response = paloalto_api(device_ip, keygen_parameter)
    key_value = ET.fromstring(response.text).find('./result/key')
    api_key = key_value.text

    return api_key


def get_config(device_ip: str, username: str, password: str) -> str:
    api_key = get_api_key(device_ip, username, password)
    export_parameter = {
        'type': 'export',
        'category': 'configuration',
        'key': api_key
    }

    config_xml = paloalto_api(device_ip, export_parameter).text

    return config_xml


def list_to_string(list_data: list) -> str:
    return ','.join(str(s) for s in list_data)


def get_member(entry: ET.Element) -> list:
    try:
        result = [member.text for member in entry]
    except:
        result = []
    return result


def export_security_rules_from_config(device_ip: str, username: str, password: str, hostname: str) -> None:
    current_date = datetime.datetime.now().strftime("%Y%m%d")
    save_file = f'./{current_date}-{hostname}-security-rules.csv'
    
    config_xml = get_config(device_ip, username, password)
    tree = ET.fromstring(config_xml)
    rulebase = tree.findall('./devices/entry/vsys/entry/rulebase/security/rules/entry')
    security_rules = []
    
    for sequence_number, rule in enumerate(rulebase, 1):
        rule_objects = [hostname, sequence_number]
        
        rule_name = str(rule.attrib.get('name'))
        disabled = get_member(rule.findall('./disabled'))
        disabled = list_to_string(disabled) if disabled else 'no'
        action = list_to_string(get_member(rule.findall('./action')))
        tag = list_to_string(get_member(rule.findall('./tag/member')))
        from_list = list_to_string(get_member(rule.findall('./from/member')))
        source_list = list_to_string(get_member(rule.findall('./source/member')))
        source_user_list = list_to_string(get_member(rule.findall('./source-user/member')))
        to_list = list_to_string(get_member(rule.findall('./to/member')))
        destination_list = list_to_string(get_member(rule.findall('./destination/member')))
        service_list = list_to_string(get_member(rule.findall('./service/member')))
        application_list = list_to_string(get_member(rule.findall('./application/member')))
        description_list = get_member(rule.findall('./description'))
        description_list = [i.replace('\n', ' ') if isinstance(i, str) else i for i in description_list]
        description = list_to_string(description_list)
        hip_profiles = list_to_string(get_member(rule.findall('./hip-profiles')))
        category = list_to_string(get_member(rule.findall('./category')))
        log_profile = list_to_string(get_member(rule.findall('./log-setting')))
        
        rule_objects += [rule_name, disabled, action, tag, from_list, source_list, source_user_list, to_list, 
                         destination_list, service_list, application_list, hip_profiles, category, description, log_profile]
        
        security_rules.append(rule_objects)
        
    with open(save_file, mode='w', newline='', encoding='utf-8') as result:
        wr = csv.writer(result)
        wr.writerow(['Hostname', 'Seq', 'Rulename', 'Disabled', 'Action', 'Tag', 'From', 'Source', 'User', 'To', 'Destination', 'Service', 'Application', 'Profiles', 'Category', 'Description', 'Log-Profile'])
        
        for rule in security_rules:
            wr.writerow(rule)
