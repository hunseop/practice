import pandas as pd
import requests
import datetime
import xml.etree.ElementTree as ET

def get_hitcount(device_ip, username, password, hostname):
    api_key = get_api_key(device_ip, username, password)
    
    command = "<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'><rule-base><entry name='security'><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>"
    export_parameter = (('type', 'op'), ('cmd', command), ('key', api_key))
    
    try:
        response = paloalto_api(device_ip, export_parameter)
        tree = ET.fromstring(response.text)
        rules = tree.findall('.//entry[@name="security"]/rules/entry')
        
        df = pd.DataFrame(columns=['Hostname', 'Rulename', 'Hit Count', 'First Hit Date', 'Last Hit Date', 'Unused days'])
        for rule in rules:
            rule_name = rule.attrib.get("name")
            hit_count = rule.find("hit-count").text
            last_hit_timestamp = int(rule.find("last-hit-timestamp").text)
            first_hit_timestamp = int(rule.find("first-hit-timestamp").text)

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
                
            df.loc[len(df)] = [hostname, rule_name, hit_count, first_hit_date, last_hit_date, unused_days]
            
        save_file = f'./{current_date}-{hostname}-hit-count.csv'
        df.to_csv(save_file, index=False)
        
    except ValueError:
        print("Please check and try again.")
