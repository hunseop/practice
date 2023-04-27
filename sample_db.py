import sqlite3
import datetime
import random
import string

# function to generate a random string of given length
def random_string(length):
    return ''.join(random.choice(string.ascii_letters) for i in range(length))

# function to generate a random IP address
def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

# list of common application names
common_apps = ["HTTP", "HTTPS", "SSH", "SMTP", "POP3", "IMAP", "DNS", "FTP", "Telnet", "RDP", "SMB", "NFS"]

# generate sample data
sample_data = []
for i in range(100):
    rule = [
        random_string(10),  # hostname
        i+1,  # sequence_number
        f"rule_{i+1}_{random_string(5)}",  # rule_name
        random.choice(['yes', 'no']),  # disabled
        random_string(10),  # action
        random_string(10),  # tag
        random_string(10),  # from_list
        random_ip(),  # source_list
        random_string(10),  # source_user_list
        random_string(10),  # to_list
        random_ip(),  # destination_list
        random_string(10),  # service_list
        random.choice(common_apps),  # application_list
        random_string(10),  # hip_profiles
        random_string(10),  # category
        random_string(100),  # description
        random_string(10),  # log_profile
    ]
    sample_data.append(rule)

# create connection and cursor objects
conn = sqlite3.connect('security_rules.db')
c = conn.cursor()

# create table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS security_rules
             (date text, hostname text, sequence_number integer, rule_name text, disabled text, action text,
              tag text, from_list text, source_list text, source_user_list text, to_list text, destination_list text,
              service_list text, application_list text, hip_profiles text, category text, description text,
              log_profile text)''')

# get current date
current_date = datetime.datetime.now().strftime("%Y%m%d")

# insert sample data into table
for rule in sample_data:
    rule.insert(0, current_date)
    c.execute('INSERT INTO security_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', rule)

# commit and close connection
conn.commit()
conn.close()
