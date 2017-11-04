from datetime import datetime
from .exceptions import *
import json
import time
import re
import socket
import subprocess
import os
import glob
import sqlite3


class PyFilter:
    def __init__(self, file="Config/config.json"):
        if not os.path.isfile(file):
            raise ConfigNotFound("{} could not be found!".format(file))
        with open(file) as config:
            data = json.load(config)
        self.settings = data["settings"]
        self.log_settings = data["logging"]
        self.rules = self.settings["rules"]
        self.ip_blacklisted = False
        self.ip_dict = {key: {} for key in self.rules}
        self.__setup_regex()
        self.__setup_database(data)

    def read_files(self, pattern_type="ssh"):
        logs = self.rules[pattern_type]["log_files"][:]
        for index, file in enumerate(logs):
            if not isinstance(file, str):
                file = file[0]
                print("Searching for files matching: {}".format(file))
                similar_files = glob.glob(file + ".[0-9]")
                logs[index] = file
                logs = logs + similar_files
        if not logs:
            print("No files to check within rule: {} - skipping".format(pattern_type.title()))
            return False
        print("Checking {} logs".format(pattern_type.title()))
        for file in logs:
            if not os.path.isfile(file):
                print("WARNING: file {} could not be found - skipping".format(file))
                continue
            with open(file) as f:
                for line in f:
                    for regex_pattern in self.regex[pattern_type]:
                        found = regex_pattern.findall(line)
                        if found:
                            found = found[0]
                            if pattern_type in ["apache", "nginx"]:
                                ip = found[0]
                                if int(found[3]) not in self.settings[pattern_type]["http_status_blocks"]:
                                    return
                                t = datetime.strptime(found[1], self.rules[pattern_type]["time_format"])
                            else:
                                ip = found[1]
                                t = datetime.strptime(found[0], self.rules[pattern_type]["time_format"])
                            this_year = datetime.now().year
                            if t.year != this_year:
                                t = t.replace(year=this_year)

                            if not self.ip_regex.match(ip):
                                ip = socket.gethostbyname(ip)

                            if ip not in self.settings["ignored_ips"]:
                                if ip not in self.ip_dict[pattern_type]:
                                    self.add_ip(ip, pattern_type)
                                self.filter(ip, pattern_type, t)
                    time.sleep(0.0001)  # Ensure it doesnt kill CPU
        return True

    def add_ip(self, ip, pattern_type):
        t = datetime(2000, 1, 1, 1, 1, 1)
        # Setup the date is a long time ago to ensure there is a time object to be compared, but not close enough to
        # Give a false positive
        self.ip_dict[pattern_type][ip] = {"amount": 0, "last_request": t}

    def find_ip(self, ip):
        if self.settings["database"] == "redis":
            return self.redis_connection.get(ip)
        cursor = self.sqlite_connection.cursor()
        cursor.execute("SELECT ip FROM banned_ip WHERE ip = ?", (ip,))
        ip = cursor.fetchone()
        cursor.close()
        return ip

    def save_ip(self, ip):
        if self.settings["database"] == "redis":
            self.redis_connection.set(ip, "IP DENIED")
            return
        cursor = self.sqlite_connection.cursor()
        try:
            cursor.execute("INSERT INTO banned_ip VALUES (?)", (ip,))
            self.sqlite_connection.commit()
        except sqlite3.IntegrityError:
            print("IP already in the database")
        finally:
            cursor.close()

    def filter(self, ip, pattern_type, time_object):
        old_time_object = self.ip_dict[pattern_type][ip]["last_request"]
        self.ip_dict[pattern_type][ip]["last_request"] = time_object
        time_since_request = (time_object - old_time_object).total_seconds()
        if time_since_request > self.settings["request_time"]:
            return  # Returns if the last request was more than the specified time
        self.ip_dict[pattern_type][ip]["amount"] += 1
        if self.ip_dict[pattern_type][ip]["amount"] == self.settings["failed_attempts"]:
            if not self.find_ip(ip):
                self.blacklist(ip)
                if self.log_settings["active"]:
                    log_message = "{}: IP: {} has been blacklisted and the firewall rules have been updated. " \
                                  "Acquired 5 bad connections via {}.\n" \
                                  .format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, pattern_type)

                    self.log(log_message)
                    print(log_message)

    def blacklist(self, ip):
        blacklist_string = "iptables -I INPUT -s {} -j {}".format(ip, self.settings["deny_type"])
        subprocess.call(blacklist_string.split())
        self.save_ip(ip)
        self.ip_blacklisted = True

    def log(self, log_message):
        config_dir = self.log_settings["directory"]
        day_dir = config_dir + "/" + datetime.now().strftime("%Y-%m-%d")
        if not os.path.isdir(config_dir):
            os.mkdir(config_dir)
        if not os.path.isdir(day_dir):
            os.mkdir(day_dir)
        file_name = day_dir + "/" + datetime.now().strftime("%Y-%m-%d %H") + ".log"
        open_type = "a" if os.path.isfile(file_name) else "w"
        with open(file_name, open_type) as file:
            file.write(log_message)

    def make_persistent(self):
        if self.ip_blacklisted:
            subprocess.call("iptables-save > Config/blacklist.v4", shell=True)
            self.ip_blacklisted = False

    def __setup_regex(self):
        self.regex = {}

        for key in self.ip_dict:
            self.regex[key] = []
            for regex in self.rules[key]["regex_patterns"]:
                if type(regex) is str:
                    self.regex[key].append(re.compile(regex))
                else:
                    regex = regex[0].format("|".join(self.rules[key][regex[1]]))
                    self.regex[key].append(re.compile(regex))

        self.ip_regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def __setup_database(self, data):
        if self.settings["database"] == "redis":
            from redis import Redis
            data = data["redis"]
            self.redis_connection = Redis(host=data["host"], db=data["database"], password=data["password"])
        elif self.settings["database"] == "sqlite":
            database = data["sqlite"]["database"]
            created = False
            if os.path.isfile(database):
                created = True
            self.sqlite_connection = sqlite3.connect(database)
            if not created:
                cursor = self.sqlite_connection.cursor()
                try:
                    cursor.execute('''CREATE TABLE banned_ip (ip text PRIMARY KEY)''')
                    self.sqlite_connection.commit()
                except Exception as exc:
                    print("The following exception as occurred;", exc)
                finally:
                    cursor.close()
        else:
            raise DatabaseConfigException("Database has to be redis or sqlite!")

    def run(self):
        sleep_time = self.settings["check_time"] / len(self.ip_dict)
        print("Will run each rule {} seconds apart".format(sleep_time))
        if self.settings["reload_iptables"]:
            if os.path.isfile("Config/blacklist.v4"):
                print("Updating firewall rules!")
                subprocess.call("iptables-restore < Config/blacklist.v4", shell=True)
        while True:
            for key in self.rules:
                if self.read_files(key):
                    time.sleep(sleep_time)
            self.make_persistent()
            print("Finished reading the rules!")
            if self.settings["run_once"]:
                return
            self.ip_dict = {key: {} for key in self.rules}
