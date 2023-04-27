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
