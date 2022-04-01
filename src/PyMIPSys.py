import mysql.connector
import configparser
import argparse
import logging
import os
import threading
import time
import json
from datetime import date, datetime, timedelta, timezone
import numpy as np
import re
import pyufw as ufw

class Monitor(threading.Thread):
    def __init__(self,config,path):
        # ufw.default(incoming='allow',outgoing='allow')
        # ufw.enable()
        threading.Thread.__init__(self)
        self.ports = config.get("PORTS").strip(' []()').split(',')
        self.period = config.getint("REFRESH_PERIOD")
        self.refresh = config.getboolean("REFRESH")
        self.running = False
        self.path = path

    def __str__(self):
        return str(ufw.status())

    def ban(self,ip):
        for port in self.ports:
            ufw.add(f'deny from {ip} to any port {port}',number=1)
    
    def unban(self,ip):
        for port in self.ports:
            ufw.delete(f'deny from {ip} to any port {port}')
    
    def run(self):
        # ufw.add('deny xxx to port 80')
        self.running = True
        while self.running:

            # get current ban_list
            ban_changed = False
            ufw_changed = False

            success = False
            tcount = 0
            while not success:
                try:
                    with open(self.path) as json_file:
                        ban_list = json.load(json_file)
                    success = True
                except FileNotFoundError:
                    ban_list = []
                    success = True
                except json.decoder.JSONDecodeError as e:
                    if tcount >= 10:
                        raise
                    tcount += 1
                    success = False
                    print(e)
                    time.sleep(1)

            

            # get current block list from ufw
            rules = ufw.get_rules()
            values = [re.findall(r"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}",x) for x in rules.values()]
            ips = []
            for ip in values:
                if len(ip) == 1:
                    ip = ip[0]
                    if ip not in [x['ip'] for x in ban_list]: # In ufw but not in ban_list
                        self.unban(ip)
                        ufw_changed = True
                    if ip not in ips:
                        ips.append(ip)
            print(f"Banned IPs: {ips}")
            # Configure ufw according to ban_list
            for idx,rule in enumerate(ban_list):
                if datetime.now() >= datetime.strptime(rule['end_time'], "%m/%d/%Y, %H:%M:%S"):
                    del ban_list[idx] # Delete from ban_list if time is due
                    ban_changed = True # Only write back if changed
                    if rule['ip'] in ips: # In banlist and ufw but endtime is over
                        self.unban(rule['ip'])
                        ufw_changed = True
                elif rule['ip'] not in ips: # in banlist but not in ufw
                    self.ban(rule['ip'])
                    ufw_changed = True

            # Write back to ban_list
            if ban_changed:
                with open(self.path,'w') as json_file:
                    json.dump(ban_list, json_file)

            # Reload if necessary
            if self.refresh and ufw_changed:
                ufw.reload()

            # Sleep before checking again
            # print(ufw.get_rules())
            time.sleep(self.period)

    def stop(self):
        self.running = False

class SshChecker(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.minutes = int(config["BANRULES"].get("MINUTES"))
        self.attempts = int(config["BANRULES"].get("ATTEMPTS"))
        self.running = False

    def getFailedLogins(self):
        # Mar 25 16:18:46 vps-f8109091 sshd[90017]: Failed password for nsproject from xxx.xxx.xxx.xxx port yyyyy ssh2
        # Mar 25 16:19:41 vps-f8109091 sshd[90041]: Failed password for invalid user admin from xxx.xxx.xxx.xxx port yyyyy ssh2
        # Mar 25 16:30:40 vps-f8109091 sshd[90460]: message repeated 2 times: [ Failed password for nsproject from xxx.xxx.xxx.xxx port yyyyy ssh2]
        # Mar  6 20:47:08 vps-f8109091 phpMyAdmin[307959]: user denied: root (mysql-denied) from xxx.xxx.xxx.xxx
        # Mar  6 21:42:02 vps-f8109091 phpMyAdmin[307937]: message repeated 7 times: [ user denied: test (mysql-denied) from xxx.xxx.xxx.xxx]

        def getTimeObject(line):
            time = re.search(r"([0-9]{2}:[0-9]{2}:[0-9]{2})", line).group()
            month = re.search(r"[A-Z][a-z]{2} ", line).group()
            day = re.search(r" [0-9]?[0-9] ", line).group()
            # logging.debug(month+day+time)
            time_object = datetime.strptime(month+day+time, '%b %d %H:%M:%S')
            time_object = time_object.replace(year=datetime.today().year) # This will probably break during newyears for a moment
            return time_object

        with open(config['SSH'].get('LOG')) as f:
            lines = f.readlines()

        failed_logins = dict()
        for line in lines:
            hit = re.search(r".*sshd\[.*\]: Failed password for .*", line)
            if hit:
                time_object = getTimeObject(line)
                minutes_diff = (datetime.now() - time_object).total_seconds() / 60.0
                if minutes_diff <= self.minutes: # We want to only see the attempts in the given time frame
                    ip = re.findall(r"[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*", line)[-1] # getting last one to prevent attacker getting smart with username
                    if ip in failed_logins.keys():
                        failed_logins[ip] += 1
                    else:
                        failed_logins[ip] = 1

            hit_repeated = re.search(r".*sshd\[.*\]: message repeated .* times: \[ Failed password for .*\]", line)
            if hit_repeated:
                time_object = getTimeObject(line)
                minutes_diff = (datetime.now() - time_object).total_seconds() / 60.0
                if minutes_diff <= self.minutes: # We want to only see the attempts in the given time frame
                    repeated = re.findall(r"repeated [0-9]*", line)[0]
                    repeated = int(repeated[9:]) # Should be good
                    ip = re.findall(r"[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*", line)[0]
                    if ip in failed_logins.keys():
                        failed_logins[ip] += repeated
                    else:
                        failed_logins[ip] = repeated

        return failed_logins

    def run(self):
        self.running = True
        refresh_period = config["SSH"].getint('REFRESH_PERIOD')
        while self.running:
            failed_logins = self.getFailedLogins()
            for ip in failed_logins.keys():
                if failed_logins[ip] >= self.attempts:
                    logging.warning(f"{ip} should be banned!")
                    banIP(ip)
            time.sleep(refresh_period)

    def stop(self):
        self.running = False

class PhpMyAdminChecker(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.minutes = int(config["BANRULES"].get("MINUTES"))
        self.attempts = int(config["BANRULES"].get("ATTEMPTS"))
        self.running = False

    def getFailedLogins(self):
        # Mar  6 20:47:08 vps-f8109091 phpMyAdmin[307959]: user denied: root (mysql-denied) from xxx.xxx.xxx.xxx
        # Mar  6 21:42:02 vps-f8109091 phpMyAdmin[307937]: message repeated 7 times: [ user denied: test (mysql-denied) from xxx.xxx.xxx.xxx]

        def getTimeObject(line):
            time = re.search(r"([0-9]{2}:[0-9]{2}:[0-9]{2})", line).group()
            month = re.search(r"[A-Z][a-z]{2} ", line).group()
            day = re.search(r" [0-9]?[0-9] ", line).group()
            # logging.debug(month+day+time)
            time_object = datetime.strptime(month+day+time, '%b %d %H:%M:%S')
            time_object = time_object.replace(year=datetime.today().year) # This will probably break during newyears for a moment
            return time_object

        with open(config['PHPMYADMIN'].get('LOG')) as f:
            lines = f.readlines()

        failed_logins = dict()
        for line in lines:
            hit = re.search(r".*phpMyAdmin\[.*\]: user denied: root \(mysql-.*\) from .*", line)
            if hit:
                time_object = getTimeObject(line)
                minutes_diff = (datetime.now() - time_object).total_seconds() / 60.0
                if minutes_diff <= self.minutes: # We want to only see the attempts in the given time frame
                    ip = re.findall(r"[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*", line)[0]
                    if ip in failed_logins.keys():
                        failed_logins[ip] += 1
                    else:
                        failed_logins[ip] = 1

            hit_repeated = re.search(r".*phpMyAdmin\[.*\]: message repeated .* times: \[ user denied: test \(mysql-.*\) from .*\]", line)
            if hit_repeated:
                time_object = getTimeObject(line)
                minutes_diff = (datetime.now() - time_object).total_seconds() / 60.0
                if minutes_diff <= self.minutes: # We want to only see the attempts in the given time frame
                    repeated = re.findall(r"repeated [0-9]*", line)[0]
                    repeated = int(repeated[9:]) # Should be good
                    ip = re.findall(r"[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*", line)[0]
                    if ip in failed_logins.keys():
                        failed_logins[ip] += repeated
                    else:
                        failed_logins[ip] = repeated

        return failed_logins

    def run(self):
        self.running = True
        refresh_period = config["PHPMYADMIN"].getint('REFRESH_PERIOD')
        while self.running:
            failed_logins = self.getFailedLogins()
            for ip in failed_logins.keys():
                if failed_logins[ip] >= self.attempts:
                    logging.warning(f"{ip} should be banned!")
                    banIP(ip)
            time.sleep(refresh_period)

    def stop(self):
        self.running = False

class JoomlaChecker(threading.Thread):
    def __init__(self,usr,passwd,db):
        threading.Thread.__init__(self)
        self.usr = usr
        self.passwd = passwd
        self.db = db
        self.minutes = int(config["BANRULES"].get("MINUTES"))
        self.attempts = int(config["BANRULES"].get("ATTEMPTS"))
        self.login()
        self.running = False

    def login(self):
        try:
            logging.info("JoomlaChecker is trying to log in")
            self.con = mysql.connector.connect(
                host="localhost",           # should be hosted on the same server
                user=self.usr,
                passwd=self.passwd,
                database=self.db
            )
        except Exception as e:
            logging.error(e)
            self.con = None
            raise

    def run(self):
        old = None
        self.running = True
        refresh_period = config['JOOMLA'].getint('REFRESH_PERIOD')
        use_UTC_time = config['JOOMLA'].getboolean('USE_UTC_TIME')
        while self.running:
            if use_UTC_time:
                time_now = datetime.utcnow()
            else:
                time_now = datetime.now()
            # get time right before reading the log for fair comparison.
            new = readJoomlaDB(self.con)
            if old != new:
                logging.debug("Difference detected, comparing...")
                for ip_address in new:
                    if len(new[ip_address]) < self.attempts:
                        logging.debug(f"{ip_address} has less than required login attempts")
                        continue # less than required attempts in total for this ip
                    elif (time_now - new[ip_address][-self.attempts]).total_seconds()/60.0 < (self.minutes):
                        logging.warning(f"{ip_address} should be banned!")
                        banIP(ip_address)
                    else:
                        logging.debug(f"{ip_address} has less than required attempts in the required timeframe")
                        continue # less than required attempts in the required timeframe.
            old = new
            time.sleep(refresh_period)
            
    def stop(self):
        self.running = False

class WordpressChecker(threading.Thread):
    def __init__(self,usr,passwd,db):
        threading.Thread.__init__(self)
        self.usr = usr
        self.passwd = passwd
        self.db = db
        self.minutes = int(config["BANRULES"].get("MINUTES"))
        self.attempts = int(config["BANRULES"].get("ATTEMPTS"))
        self.login()
        self.running = False

    def login(self):
        try:
            logging.info("WordpressChecker is trying to log in")
            self.con = mysql.connector.connect(
                host="localhost",           # should be hosted on the same server
                user=self.usr,
                passwd=self.passwd,
                database=self.db
            )
        except Exception as e:
            logging.error(e)
            self.con = None
            raise

    def run(self):
        old = None
        self.running = True
        sliding_window = dict()
        refresh_period = config["WORDPRESS"].getint('REFRESH_PERIOD')
        while self.running:
            new = readWordpressDB(self.con)

            ### Sliding window to check attempts per minute
            if old is not None:
                for occurrence in new:
                    old_occurrence = next((item for item in old if item['client_ip'] == occurrence['client_ip']),None)
                    if old_occurrence is None:
                        logging.debug(f"First time occurrence of {occurrence['client_ip']}")
                        sliding_window[occurrence['client_ip']] = [0]*int(60/refresh_period)
                        continue
                    else:
                        del sliding_window[occurrence['client_ip']][0] # delete oldest
                        delta_attempts = int(occurrence['attempts']) - int(old_occurrence['attempts'])
                        sliding_window[occurrence['client_ip']].append(delta_attempts) # add newest
                        attempts_per_minute = np.sum(sliding_window[occurrence['client_ip']])
                        if attempts_per_minute >= self.attempts:
                            logging.warning(f"{occurrence['client_ip']} should be banned!")
                            banIP(occurrence['client_ip'])
            else:
                # initialise the sliding window
                for occurrence in new:
                    sliding_window[occurrence['client_ip']] = [0]*int(60/refresh_period)
    
            old = new
            time.sleep(refresh_period)
            
    def stop(self):
        self.running = False

def read_ini(path):
    '''Reads the settings file
    
    :param path: The file location of the settingsfile'''

    config = configparser.ConfigParser()
    config.read(path)
    return config

def readWordpressDB(connection):
    '''Reads the database of our website
    
    :param username: The username to acces the mysql db
    :param password: The password to acces the mysql db
    :param database: The database we want to read'''
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM `wp_wsal_occurrences` WHERE event_type='failed-login'")
    occurrences = cursor.fetchall()

    output = []
    keys = []
    for occurrence in occurrences:
        cursor.execute(f"SELECT * FROM `wp_wsal_metadata` WHERE occurrence_id = {occurrence['id']} AND name='Attempts'")
        metadata = cursor.fetchall()[0] # with this filter it should only have one value
        # logging.debug(f"{occurrence['client_ip']} has {metadata['value']} failed attempts!")
        
        ##  Some occurrences has multiple forms of failed-login attempts
        #   Here we add them together
        if occurrence['client_ip'] in keys:
            idx = keys.index(occurrence['client_ip'])
            output[idx]['attempts'] += metadata['value']
        else:
            output.append({'client_ip':occurrence['client_ip'],'attempts':metadata['value']})
            keys.append(occurrence['client_ip'])

    connection.commit() # Without this we can't read new data
    # print(output)
    return output

def readJoomlaDB(connection):
    '''Reads the database of our website
    
    :param username: The username to acces the mysql db
    :param password: The password to acces the mysql db
    :param database: The database we want to read'''
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM `j_action_logs` WHERE message_language_key='PLG_ACTIONLOG_JOOMLA_USER_LOGIN_FAILED' ORDER BY 'id' ASC")
    occurrences = cursor.fetchall()

    output = {}
    for occurrence in occurrences:
        if (occurrence['ip_address'] in output):
            output[occurrence['ip_address']].append(occurrence['log_date'])
        else:
            output[occurrence['ip_address']] = [occurrence['log_date']]

    connection.commit() # Without this we can't read new data
    return output

def banIP(IP):
    path = config['BANRULES'].get('BANLIST_LOCATION')
    success = False
    tcount = 0
    while not success:
        try:
            with open(path) as json_file:
                ban_list = json.load(json_file)
            success = True
        except FileNotFoundError:
            ban_list = []
            success = True
        except json.decoder.JSONDecodeError as e:
            if tcount >= 10:
                raise
            print(e)
            success = False
            tcount += 1
            time.sleep(1)

    banned_ips = [d['ip'] for d in ban_list] # Only ban if not already banned
    if IP not in banned_ips:
        endtime = datetime.now() + timedelta(seconds=int(config['BANRULES'].get('DURATION')))
        data = {
            'ip': IP,
            'end_time': endtime.strftime("%m/%d/%Y, %H:%M:%S")
            }
        ban_list.append(data)
    else:
        logging.warning("IP already banned!") # This should not happen during actual employement

    with open(path,'w') as json_file:
        json.dump(ban_list, json_file)

def PyMIPSys(username,password,config,seconds=None):
    
    ### Parsing for the password
    if not password:
        password = input("Please enter the database password:\n")

    ### Turning on the correct protocols
    if config["WORDPRESS"].getboolean("ENABLED"):
        logging.info("Wordpress enabled")
        wpc = WordpressChecker(usr=username,passwd=password,db=config["WORDPRESS"].get("DB"))
        wpc.start()
    if config["JOOMLA"].getboolean("ENABLED"):
        logging.info("Joomla enabled")
        jl = JoomlaChecker(usr=username,passwd=password,db=config["JOOMLA"].get("DB"))
        jl.start()
    if config["PHPMYADMIN"].getboolean("ENABLED"):
        logging.info("Phpmyadmin enabled")
        pmac = PhpMyAdminChecker()
        pmac.start()
    if config["MONITOR"].getboolean("ENABLED"):
        logging.info("Monitor enabled")
        mon = Monitor(config["MONITOR"],config["BANRULES"].get("BANLIST_LOCATION"))
        mon.start()
    if config["SSH"].getboolean("ENABLED"):
        logging.info("SSH enabled")
        sshc = SshChecker()
        sshc.start()  

    print("Started!")
    if seconds is None:
        while True:
            time.sleep(1)
    else:
        time.sleep(seconds) # For debugging just run a few seconds

    ### Turning off the correct protocols
    if config["WORDPRESS"].getboolean("ENABLED"):
        wpc.stop()
    if config["JOOMLA"].getboolean("ENABLED"):
        jl.stop()
    if config["PHPMYADMIN"].getboolean("ENABLED"):
        pmac.stop() 
    if config["MONITOR"].getboolean("ENABLED"):
        mon.stop()
    if config["SSH"].getboolean("ENABLED"):
        sshc.stop() 

    print("Done.")

if __name__ =="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u","--user", help="Username of the database")
    parser.add_argument("-p","--password", help="Use a password to log in to the database")
    args = parser.parse_args()
    config = read_ini(os.path.join(os.getcwd(),'ban_settings.ini'))

    try:                    # Try for python >3.8
        logging.basicConfig(filename=config["LOGGING"].get("FILENAME"),encoding="utf-8",level=logging.DEBUG)    # Logging so we can debug a bit better
    except ValueError:      # Except ValueError if python <= 3.8
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        handler = logging.FileHandler(config["LOGGING"].get("FILENAME"),'w','utf-8')
        root_logger.addHandler(handler)

    PyMIPSys(args.user,args.password,config)