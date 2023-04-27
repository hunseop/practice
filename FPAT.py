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

## Load Configuration
os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYWORD_DIC = f'{BASE_DIR}'

if os.path.isfile('./config.json'):
    with open('config.json') as conf_file:
        config = json.load(conf_file)
else:
    print("Please check config file.")
    os.system('pause')
    exit()

danger_ports = config['dangerous_ports']
search_ports = config['search_ports']
wide_criteria = int(config['wide_criteria'])

class Node(object):
    def __init__(self, key, data=None):
        self.key = key
        self.data = data
        self.children = {}

class Trie:
    def __init__(self):
        self.head = Node(None)
    
    def insert(self, string):
        current_node = self.head
        
        for char in string:
            if char not in current_node.children:
                current_node.children[char] = Node(char)
            current_node = current_node.children[char]
        current_node.data = string
    
    def search(self, string):
        current_node = self.head
        
        for char in string:
            if char in current_node.children:
                current_node = current_node.children[char]
            else:
                return False
        
        if current_node.data:
            return True
        else:
            return False
    
    def starts_with(self, prefix):
        current_node = self.head
        words = []
        
        for p in prefix:
            if p in current_node.children:
                current_node = current_node.children[p]
            else:
                return None
        
        current_node = [current_node]
        next_node = []
        while True:
            for node in current_node:
                if node.data:
                    words.append(node.data)
                next_node.extend(list(node.children.values()))
            if len(next_node) != 0:
                current_node = next_node
                next_node = []
            else:
                break
        
        return words

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

def save_config(device_ip, username, password, hostname):
    save_file = f'./{current_date}-{hostname}-running-config.xml'
    try:
        parse_xml = xml.dom.minidom.parseString(get_config(device_ip, username, password))
        config_xml = parse_xml.toprettyxml()
        
        with open(save_file, mode='w', encoding='utf8') as file:
            file.write(config_xml)
    
    except:
        raise ValueError

def get_member(entry):
    try:
        result = [ member.text for member in entry ]
    except:
        result = []
    
    return result

def list_to_string(list_data):
    return ','.join(str(s) for s in list_data)

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

def get_hitcount(device_ip, username, password, hostname):
    save_file = f'./{current_date}-{hostname}-hit-count.csv'
    command = "<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'><rule-base><entry name='security'><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>"
    api_key = get_api_key(device_ip, username, password)
    export_parameter = (
        ('type', 'op'),
        ('cmd', command),
        ('key', api_key)
    )

    try:
        response = paloalto_api(device_ip, export_parameter)
        tree = ET.fromstring(response.text)
        rules = tree.findall('./result/rule-hit-count/vsys/entry/rule-base/entry/rules/entry')
        
        with open(save_file, mode='w', newline='') as result:
            wr = csv.writer(result)
            wr.writerow(['Hostname', 'Rulename', 'Hit Count', 'First Hit Date', 'Last Hit Date', 'Unused days'])
            for rule in rules:
                rule_name = str(rule.attrib.get("name"))
                rule_info = get_member(rule)
                hit_count = rule_info[1]
                last_hit_timestamp = int(rule_info[2])
                first_hit_timestamp = int(rule_info[4])
                
                if first_hit_timestamp == 0:
                    unused_days = "Never"
                else:
                    unused_days = (datetime.datetime.now()-datetime.datetime.fromtimestamp(last_hit_timestamp)).days
                
                if last_hit_timestamp == 0:
                    last_hit_date = "-"
                else:
                    last_hit_date = datetime.datetime.fromtimestamp(last_hit_timestamp).strftime('%Y-%m-%d')
                
                if first_hit_timestamp == 0:
                    first_hit_date = "-"
                else:
                    first_hit_date = datetime.datetime.fromtimestamp(first_hit_timestamp).strftime('%Y-%m-%d')
                
                wr.writerow([hostname, rule_name, hit_count, first_hit_date, last_hit_date, unused_days])
    
    except ValueError:
        print("Please check and try again.")

def expand_range_port(object):
    try:
        pro = str(object.split('-')[0])
        start = int(object.split('-')[1])
        end = int(object.split('-')[2])
        port_list = [ pro+'-'+str(single_port) for single_port in range(start, end+1)]
    except:
        return False
    
    return port_list

def analyze_search_port(device_ip, username, password, hostname):
    save_file = f"./{current_date}-{hostname}-search-port.csv"
    p = re.compile('\w{1,5}-\d{1,5}-\d{1,5}')
    
    tree = ET.fromstring(get_config(device_ip, username, password))
    rulebase = tree.findall('./devices/entry/vsys/entry/rulebase/security/rules/entry')
    rules = []
    
    for port in search_ports:
        if p.match(port):
            danger_ports.remove(port)
            danger_ports.extend(expand_range_port(port))
    
    # export policy
    for rule in rulebase:
        rule_name = rule.attrib.get ('name')
        services = []
        applications = []
        
        rule_entry = rule.findall('./service/member')
        for j in rule_entry:
            services.append(j.text)
        
        rule_entry = rule.findall('./application/member')
        for j in rule_entry:
            applications.append(j.text)
        
        rules.append([hostname, rule_name, services, applications])
    
    # export service
    services = tree.findall('./devices/entry/vsys/entry/service/entry')
    service_objects = []
    for service in services:
        service_info = service.attrib.get('name')
        service_name = service_info
        service_members = []
        
        service_entry = service.findall('./protocol/tcp/port')
        for j in service_entry:
            service_member = j.text.split(',')
            for k in service_member:
                service_members.append('TCP-'+k)
        
        service_entry = service.findall('./protocol/udp/port')
        for j in service_entry:
            service_member = j.text.split(',')
            for k in service_member:
                service_members.append('UDP-'+k)
        
        service_objects.append([service_name, service_members])
    
    # export service group
    service_groups = tree.findall('./devices/entry/vsys/entry/service-group/entry')
    service_group_objects = []
    for service_group in service_groups:
        group_name = service_group.attrib.get('name')
        group_member = []
        
        group_entry = service_group.findall('./members/member')
        for j in group_entry:
            group_member.append(j.text)
        
        service_group_objects.append([group_name, group_member])
        
    for i in range(0, len(service_group_objects)):
        conv_services = []
        for j in service_group_objects[i][1]:
            for k in range(0, len(service_objects)):
                if j == service_objects[k][0]:
                    conv_services.extend(service_objects[k][1])
        service_group_objects[i].append(conv_services)
    
    with open(save_file, mode='w', newline='') as result:
        wr = csv.writer(result)
        wr.writerow(['Hostname', 'Rule name', 'Service', 'Application', 'Match Port', 'Count'])
        
        with progressbar(length=len(rules)) as progress:
            for i in range(0, len(rules)):
                extended_service = []
                new_extended_service = []
                
                for j in rules[i][2]:
                    for k in range(0, len(service_group_objects)):
                        if j == service_group_objects[k][0]:
                            extended_service.extend(service_group_objects[k][2])
                    
                    for l in range(0, len(service_objects)):
                        if j == service_objects[l][0]:
                            extended_service.extend(service_objects[l][1])
                    
                    if j == 'application-default' or j == 'any' or j == 'Any':
                        extended_service.extend([j])
                
                extended_service = set(extended_service)
                extended_service = list(extended_service)
                
                for m in extended_service:
                    if p.match(m):
                        new_extended_service.extend(expand_range_port(m))
                    else:
                        new_extended_service.append(m)
                
                service_trie = Trie()
                for s_word in new_extended_service:
                    service_trie.insert(s_word)
                    
                    matched_list = []
                    for j in search_ports:
                        j = j.rstrip('\n')
                        if service_trie.search(j):
                            matched_list.append(j)
                    
                    match_count = len(matched_list)
                    match_result = ','.join(s for s in matched_list)
                    rules[i][2] = str(','.join(s for s in rules[i][2]))
                    rules[i][3] = str(','.join(s for s in rules[i][3]))
                    
                    rules[i].append(match_result)
                    rules[i].append(match_count)
                    
                    wr.writerow(rules[i])
                    progress.update(1)

def export_danger_port_rules(device, username, password, hostname):
    save_file = f'./{current_date}-{hostname}-danger-port.csv'
    p = re.compile('\w{1,5}-\d{1,5}-\d{1,5}')
    
    tree = ET.fromstring(get_config(device, username, password))
    rulebase = tree.findall('./devices/entry/vsys/entry/rulebase/security/rules/entry')
    rules = []
    
    danger_list = danger_ports
    
    for i in range(0, len(danger_list)):
        for j in danger_list[i]:
            if p.match(j):
                danger_list[i].remove(j)
                danger_list[i].extend(expand_range_port(j))
    
    with open(save_file, mode='w', newline='') as result:
        wr = csv.writer(result)
        wr.writerow(['Hostname', 'Rule name', 'Service', 'Application', 'FTP', 'FTP(Count)', 'DB', 'DB(Count)', 'Remote', 'Remote(Count)', 'Mail', 'Mail(Count)', 'Share', 'Share(Count)', 'Wide port','Wide'])
    
        # export policy
        for rule in rulebase:
            rule_name = rule.attrib.get('name')
            services = []
            applications = []
            
            rule_entry = rule.findall('./service/member')
            for j in rule_entry:
                services.append(j.text)
                
            rule_entry = rule.findall('./application/member')
            for j in rule_entry:
                applications.append(j.text)
            
            rules.append([hostname, rule_name, services, applications])
        
    # export service
    services = tree.findall('./devices/entry/vsys/entry/service/entry')
    service_objects = []
    for service in services:
        service_info = service.attrib.get('name')
        service_name = service_info
        service_members = []
        
        service_entry = service.findall('./protocol/tcp/port')
        for j in service_entry:
            service_member = j.text.split(',')
            for k in service_member:
                service_members.append('TCP-'+k)
        
        service_entry = service.findall('./protocol/udp/port')
        for j in service_entry:
            service_member = j.text.split(',')
            for k in service_member:
                service_members.append('UDP-'+k)
        
        service_objects.append([service_name, service_members])
    
    # export service group
    service_groups = tree.findall('./devices/entry/vsys/entry/service-group/entry')
    service_group_objects = []
    for service_group in service_groups:
        group_name = service_group.attrib.get('name')
        group_member = []
        
        group_entry = service_group.findall('./members/member')
        for j in group_entry:
            group_member.append(j.text)
        
        service_group_objects.append([group_name, group_member])
    
    for i in range(0, len(service_group_objects)):
        conv_services = []
        for j in service_group_objects[i][1]:
            for k in range(0, len(service_objects)):
                if j == service_objects[k][0]:
                    conv_services.extend(service_objects[k][1])
        service_group_objects[i].append(conv_services)
    
    with progressbar(length=len(rules)) as progress:
        for i in range(0, len(rules)):
            extended_service = []
            new_extended_service = []
            
            for j in rules[i][2]:
                for k in range(0, len(service_group_objects)):
                    if j == service_group_objects[k][0]:
                        extended_service.extend(service_group_objects[k][2])
                
                for l in range(0, len(service_objects)):
                    if j == service_objects[l][0]:
                        extended_service.extend(service_objects[l][1])
                
                if j == 'application-default' or j == 'any' or j == 'Any':
                    extended_service.extend([j])
            
            extended_service = set(extended_service)
            extended_service = list(extended_service)
            
            for m in extended_service:
                if p.match(m):
                    new_extended_service.extend(expand_range_port(m))
                else:
                    new_extended_service.append(m)
            
            service_trie = Trie()
            for s_word in new_extended_service:
                service_trie.insert(s_word)
            
            ftp_port = []
            db_port = []
            remote_port = []
            mail_port = []
            share_port = []
            
            wide_range_port = len(new_extended_service)
            if wide_range_port >= 1000 or j == 'any' or j == 'Any':
                wide_state = "O"
            else:
                wide_state = "X"
                
            for j in danger_list[0]:
                j = j.rstrip('\n')
                if service_trie.search(j):
                    ftp_port.append(j)

            for j in danger_list[1]:
                j = j.rstrip('\n')
                if service_trie.search(j):
                    db_port.append(j)

            for j in danger_list[2]:
                j = j.rstrip('\n')
                if service_trie.search(j):
                    remote_port.append(j)

            for j in danger_list[3]:
                j = j.rstrip('\n')
                if service_trie.search(j):
                    mail_port.append(j)

            for j in danger_list[4]:
                j = j.rstrip('\n')
                if service_trie.search(j):
                    share_port.append(j)
            
            ftp_count = len(ftp_port)
            db_count = len(db_port)
            remote_count = len(remote_port)
            mail_count = len(mail_port)
            share_count = len(share_port)
            ftp_result = ','.join(s for s in ftp_port)
            db_result = ','.join(s for s in db_port)
            remote_result = ','.join(s for s in remote_port)
            mail_result = ','.join(s for s in mail_port)
            share_result = ','.join(s for s in share_port)
            
            rules[i][2] = str(','.join(s for s in rules[i][2]))
            rules[i][3] = str(','.join(s for s in rules[i][3]))
            
            rules[i].append(ftp_result)
            rules[i].append(ftp_count)
            rules[i].append(db_result)
            rules[i].append(db_count)
            rules[i].append(remote_result)
            rules[i].append(remote_count)
            rules[i].append(mail_result)
            rules[i].append(mail_count)
            rules[i].append(share_result)
            rules[i].append(share_count)
            rules[i].append(wide_state)
            rules[i].append(wide_range_port)
            
            wr.writerow(rules[i])
            progress.update(1)

def export_wide_open_rules(device, username, password, hostname):
    save_file = f'./{current_date}-{hostname}-wide-open.csv'
    tree = ET.fromstring(get_config(device, username, password))
    rulebase = tree.findall('./devices/entry/vsys/entry/rulebase/security/rules/entry')
    rules = []
    
    single_ip_pattern = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    range_ip_pattern = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    network_pattern = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|2[0-9]|1[0-9]|[1-9])$"
    network_pattern_2 = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)_(3[0-2]|2[0-9]|1[0-9]|[1-9])$"
    
    with open(save_file, mode='w', newline='') as result:
        wr = csv.writer(result)
        wr.writerow(['Hostname', 'Rule name', 'Source', 'Destination', 'Source IP Range', 'Wide Range Source', 'Unknown Source', 'Destination IP Range', 'Wide Range Destination', 'Unknown Destination'])
        
        # export policy
        for rule in rulebase:
            rule_info = rule.attrib.get('name')
            rule_name = rule_info
            sources = []
            destinations = []
            
            rule_entry = rule.findall('./source/member')
            for j in rule_entry:
                sources.append(j.text)
            
            rule_entry = rule.findall('./destination/member')
            for j in rule_entry:
                destinations.append(j.text)
            
            rules.append([hostname, rule_name, sources, destinations])
        
        # export address group
        address_groups = tree.findall('./device/entry/vsys/entry/address-group/entry')
        address_group_objects = []
        for address_group in address_groups:
            group = address_group.attrib.get('name')
            group_name = group
            group_member = []
            
            group_entry = address_group.findall('./static/member')
            for j in group_entry:
                group_member.append(j.text)
                
            address_group_objects.append([group_name, group_member])
            
        address_list = tree.findall('./device/entry/vsys/entry/address/entry')
        address_objects = []
        for address in address_list:
            ip = address.attrib.get('name')
            ip_name = ip
            ip_member = []
            
            ip_entry = address.findall('./ip-range')
            for j in ip_entry:
                ip_member.append(j.text)
            
            ip_entry = address.findall('./ip-netmask')
            for j in ip_entry:
                ip_member.append(j.text)
            
            address_objects.append([ip_name, ip_member])
        
        address_name_trie = Trie()
        address_dict = dict()
        for address in address_objects:
            address_name = address[0]
            address_value = address[1]
            address_dict[address_name] = address_value
            address_name_trie.insert(address_name)
            
        address_group_name_trie = Trie()
        max_loop = 0
        val_state = True
        group_dict = dict()
        for address_group in address_group_objects:
            address_group_name = address_group[0]
            address_group_value = address_group[1]
            group_dict[address_group_name] = address_group_value
            address_group_name_trie.insert(address_group_name)
        
        while val_state and max_loop < 10:
            val_state = False
            
            for i in range(0, len(address_group_objects)):
                group_name = address_group_objects[i][0]
                group_list = address_group_objects[i][1]
                if len(group_list) > 1:
                    for group_entry in group_list:
                        if address_group_name_trie.search(group_entry):
                            address_group_objects[i][1].remove(group_entry)
                            address_group_objects[i][1].extend(group_dict[group_entry])
                
                elif len(group_list) == 0:
                    pass
            
                else:
                    group = group_list[0]
                    if address_group_name_trie.search(group):
                        address_group_objects[i][1].remove(group)
                        address_group_objects[i][1].extend(group_dict[group])
                
                for j in address_group_objects[i][1]:
                    if address_group_name_trie.search(j):
                        val_state = True
            
            max_loop += 1
        
        # trie initialization
        address_group_name_trie = Trie()
        group_dict = dict()
        for address_group in address_group_objects:
            address_group_name = address_group[0]
            address_group_value = address_group[1]
            group_dict[address_group_name] = address_group_value
            address_group_name_trie.insert(address_group_name)
        
        for rule_number in range(0, len(rules)):
            source_object_list = rules[rule_number][2]
            destination_object_list = rules[rule_number][3]
            extend_source_object_list = []
            extend_destination_object_list = []
            converted_source_list = []
            converted_destination_list = []
            
            for source in source_object_list:
                if address_group_name_trie.search(source):
                    extend_source_object_list.extend(group_dict[source])
                else:
                    extend_source_object_list.extend([source])
            
            for destination in destination_object_list:
                if address_group_name_trie.search(destination):
                    extend_destination_object_list.extend(group_dict[destination])
                else:
                    extend_destination_object_list.extend([destination])
            
            for new_source in extend_source_object_list:
                if new_source in address_dict.keys():
                    converted_source_list.extend(address_dict[new_source])
                else:
                    converted_source_list.extend([new_source])
            
            for new_destination in extend_destination_object_list:
                if new_destination in address_dict.keys():
                    converted_destination_list.extend(address_dict[new_destination])
                else:
                    converted_destination_list.extend([new_destination])
            
            rules[rule_number].append(converted_source_list)
            rules[rule_number].append(converted_destination_list)
        
        with progressbar(length=len(rules)) as progress:
            for i in range(0, len(rules)):
                source_host_range = 0
                source_host_state = True
                destination_host_range = 0
                destination_host_state = True
                
                source = rules[i][4]
                destinations = rules[i][5]
                
                for j in source:
                    if address_group_name_trie.search(j):
                        group_members = group_dict[j]
                        for k in group_members:
                            if re.search(network_pattern, k):
                                netmask = k.split('/')[1]
                                a = (32-int(netmask))
                                source_host_range += (2 ** a)
                            elif re.search(range_ip_pattern, k):
                                start = k.split('-')[0]
                                end = k.split('-')[1]
                                source_host_range += int(ipaddress.ip_address(end)) - int(ipaddress.ip_address(start)) + 1
                            elif re.search(single_ip_pattern, k):
                                source_host_range += 1
                            elif k == 'any':
                                source_host_range += 4294967296
                            else:
                                source_host_state = False
                    
                    elif address_name_trie.search(j):
                        address_member = address_dict[j][0]
                        address_member = str(address_member)
                        if re.search(network_pattern, address_member):
                            netmask = address_member.split('/')[1]
                            a = (32-int(netmask))
                            source_host_range += (2 ** a)
                        elif re.search(range_ip_pattern, address_member):
                            start = address_member.split('-')[0]
                            end = address_member.split('-')[1]
                            source_host_range += int(ipaddress.ip_address(end)) - int(ipaddress.ip_address(start)) + 1
                        elif re.search(single_ip_pattern, address_member):
                            source_host_range += 1
                        elif address_member == 'any':
                            source_host_range += 4294967296
                        else:
                            source_host_state = False
                            
                    elif re.search(network_pattern, j):
                        netmask = j.split('/')[1]
                        a = (32-int(netmask))
                        source_host_range += (2 ** a)
                    
                    elif re.search(network_pattern_2, j):
                        netmask = j.split('_')[1]
                        a = (32-int(netmask))
                        source_host_range += (2 ** a)
                    
                    elif re.search(range_ip_pattern, j):
                        start = j.split('-')[0]
                        end = j.split('-')[1]
                        source_host_range += int(ipaddress.ip_address(end)) - int(ipaddress.ip_address(start)) + 1
                    
                    elif re.search(single_ip_pattern, j):
                        source_host_range += 1
                        
                    elif j == 'any':
                        source_host_range += 4294967296
                        
                    else:
                        source_host_state = False
                        
                for j in destinations:
                    if address_group_name_trie.search(j):
                        group_members = group_dict[j]
                        for k in group_members:
                            if re.search(network_pattern, k):
                                netmask = k.split('/')[1]
                                a = (32-int(netmask))
                                destinations_host_range += (2 ** a)
                            elif re.search(range_ip_pattern, k):
                                start = k.split('-')[0]
                                end = k.split('-')[1]
                                destinations_host_range += int(ipaddress.ip_address(end)) - int(ipaddress.ip_address(start)) + 1
                            elif re.search(single_ip_pattern, k):
                                destinations_host_range += 1
                            elif k == 'any':
                                destinations_host_range += 4294967296
                            else:
                                destinations_host_state = False
                    
                    elif address_name_trie.search(j):
                        address_member = address_dict[j][0]
                        address_member = str(address_member)
                        if re.search(network_pattern, address_member):
                            netmask = address_member.split('/')[1]
                            a = (32-int(netmask))
                            destinations_host_range += (2 ** a)
                        elif re.search(range_ip_pattern, address_member):
                            start = address_member.split('-')[0]
                            end = address_member.split('-')[1]
                            destinations_host_range += int(ipaddress.ip_address(end)) - int(ipaddress.ip_address(start)) + 1
                        elif re.search(single_ip_pattern, address_member):
                            destinations_host_range += 1
                        elif address_member == 'any':
                            destinations_host_range += 4294967296
                        else:
                            destinations_host_state = False
                            
                    elif re.search(network_pattern, j):
                        netmask = j.split('/')[1]
                        a = (32-int(netmask))
                        destinations_host_range += (2 ** a)
                    
                    elif re.search(network_pattern_2, j):
                        netmask = j.split('_')[1]
                        a = (32-int(netmask))
                        destinations_host_range += (2 ** a)
                    
                    elif re.search(range_ip_pattern, j):
                        start = j.split('-')[0]
                        end = j.split('-')[1]
                        destinations_host_range += int(ipaddress.ip_address(end)) - int(ipaddress.ip_address(start)) + 1
                    
                    elif re.search(single_ip_pattern, j):
                        destinations_host_range += 1
                        
                    elif j == 'any':
                        destinations_host_range += 4294967296
                        
                    else:
                        destinations_host_state = False
                
                rules[i][2] = str(','.join(s for s in rules[i][2]))
                rules[i][3] = str(','.join(s for s in rules[i][3]))
                rules[i].pop(4)
                rules[i].pop(4)
                rules[i].append(source_host_range)
                if source_host_range > wide_criteria:
                    rules[i].append("O")
                else:
                    rules[i].append("X")
                
                if source_host_state:
                    rules[i].append("X")
                else:
                    rules[i].append("O")
                
                rules[i].append(destinations_host_range)
                if destinations_host_range > wide_criteria:
                    rules[i].append("O")
                else:
                    rules[i].append("X")
                
                if destinations_host_state:
                    rules[i].append("X")
                else:
                    rules[i].append("O")
                
                wr.writerow(rules[i])
                progress.update(1)

def list_to_string(list_data):
    return ','.join(str(s) for s in list_data)

def list_to_string_2(list_data):
    new_list = [list_data[0]]
    for data in list_data[1:]:
        new_data = ','.join(str(s) for s in data)
        new_list.append(new_data)

    return new_list

def analyze_shadow_rule(device_ip, username, password, hostname):
    
    current_date = datetime.datetime.now().strftime("%Y%m%d")
    result_file = './' + current_date + '_' + hostname + '_shadow.csv'
    
    upper_rule_count = 1
    total_shadow_result = []
    
    ## 1. export security rules
    tree = ET.fromstring(get_config(device_ip, username, password))
    rulebase = tree.findall('./devices/entry/vsys/entry/rulebase/security/rules/entry')
    security_rules = []
    sequence_number = 1
    
    for rule in rulebase:
        rule_objects = [hostname]
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
        description_list = [ i.replace('.\n',' ') if type(i) is str else i for i in description_list ]
        
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
        rule_objects.append(list_to_string(description_list))
        security_rules.append(rule_objects)
        sequence_number += 1
    
    for rule_count in range(0, len(security_rules)):
        shadow_state = False
        upper_rule_source = security_rules[rule_count][5]
        upper_rule_user = security_rules[rule_count][6]
        upper_rule_destination = security_rules[rule_count][8]
        upper_rule_service = security_rules[rule_count][9]
        upper_rule_application = security_rules[rule_count][10]

        lower_rule_list = []
        for lower_number in range(rule_count+1, len(security_rules)):
            lower_rule_source = security_rules[lower_number][5]
            lower_rule_user = security_rules[lower_number][6]
            lower_rule_destination = security_rules[lower_number][8]
            lower_rule_service = security_rules[lower_number][9]
            lower_rule_application = security_rules[lower_number][10]
            
            if ((upper_rule_source == lower_rule_source)
                and (upper_rule_user == lower_rule_user)
                and (upper_rule_destination == lower_rule_destination)
                and (upper_rule_service == lower_rule_service)
                and (upper_rule_application == lower_rule_application)
                ):
                shadow_state = True
                lower_rule_list.append(security_rules[lower_number])
        
        if shadow_state:
            upper_rule = list_to_string_2(security_rules[rule_count])
            shadow_info = [upper_rule_count, 'upper_rule']
            total_shadow_result.append(shadow_info + upper_rule)
            print(shadow_info + upper_rule)
            for lower_rule in lower_rule_list:
                lower_rule = list_to_string_2(lower_rule)
                shadow_info = [upper_rule_count, 'lower_rule']
                total_shadow_result.append(shadow_info + lower_rule)
                print(shadow_info + lower_rule)
            
            upper_rule_count += 1
    
    with open(result_file, mode = 'w', newline = '', encoding = 'utf-8-sig') as result:
        wr = csv.writer(result)
        wr.writerow(['Seq', 'Type', 'Rule name', 'Disabled', 'Action', 'Tag', 'From', 'Source', 'User', 'To', 'Destination', 'Service', 'Application', 'Description'])
        for rule in total_shadow_result:
            wr.writerow(rule)

def show_banner():
    print('[ FPAT ]')
    
def validate_ip_address(ip_string):
    try:
        ipaddress.ip_address(ip_string)
        return ip_string

    except:
        raise typer.BadParameter("Invalid IP address")
    
def main(
    device: str = typer.Option(..., prompt=True, callback=validate_ip_address),
    hostname: str = typer.Option(default="", help="장비명", show_default=False, prompt="Hostname"),
    username: str = typer.Option(default="", help="계정명", show_default=False, prompt=True),
    password: str = typer.Option(default="", help="패스워드", show_default=False, prompt=True, hide_input=True),
    command: str = typer.Option(default="", help="사용할 기능")
):
    if get_api_key(device, username, password):
        print(f"Connect {device}")
    else:
        raise typer.BadParameter()
    
    if command:
        print(f"Start Command : {command}")
    else:
        print("")
        print("[ Command Menu ]")
        print("1. running-config")
        print("2. security-rules")
        print("3. hit-count")
        print("4.")