from datetime import datetime
from .exceptions import ConfigNotFound, DatabaseConfigException
from .database import SqliteConnection, RedisConnection
import json
import time
import re
import socket
import subprocess
import os
import threading


class PyFilter:
    def __init__(self, file="Config/config.json"):
        if not os.path.isfile(file):
            raise ConfigNotFound("{} could not be found!".format(file))
        with open(file) as config:
            data = json.load(config)
        self.settings = data["settings"]
        self.log_settings = data["logging"]
        self.rules = self.settings["rules"]
        self.lock = threading.Lock()
        self.ip_blacklisted = False
        self.ip_dict = {key: {} for key in self.rules}
        self.__setup_regex()
        self.__setup_database(data)

    def read_files(self, pattern_type="ssh"):
        file = self.rules[pattern_type]["log_file"]
        if not file:
            print("No file to check within rule: {}".format(pattern_type.title()))
            return
        print("Checking {} logs".format(pattern_type.title()))
        if not os.path.isfile(file):
            print("WARNING: file {} could not be found".format(file))
            return
        inode = os.stat(file).st_ino
        with open(file) as f:
            while True:
                where = f.tell()
                line = f.readline()
                if not line:
                    if self.settings["run_once"]:
                        return
                    if inode != os.stat(file).st_ino:
                        f.seek(0)
                        inode = os.stat(file).st_ino
                        continue
                    time.sleep(1)
                    f.seek(where)
                    continue
                else:
                    for regex_pattern in self.regex[pattern_type]:
                        found = regex_pattern.findall(line)
                        if found:
                            found = found[0]
                            self.filter(pattern_type, found)
                time.sleep(0.0001)  # Ensure it doesnt kill CPU

    def add_ip(self, ip, pattern_type):
        t = datetime(2000, 1, 1, 1, 1, 1)
        # Setup the date is a long time ago to ensure there is a time object to be compared, but not close enough to
        # Give a false positive
        self.ip_dict[pattern_type][ip] = {"amount": 0, "last_request": t}

    def filter(self, pattern_type, found):
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
            self.check(ip, pattern_type, t)

    def check(self, ip, pattern_type, time_object):
        old_time_object = self.ip_dict[pattern_type][ip]["last_request"]
        self.ip_dict[pattern_type][ip]["last_request"] = time_object
        time_since_request = (time_object - old_time_object).total_seconds()
        if time_since_request > self.settings["request_time"]:
            return  # Returns if the last request was more than the specified time
        self.ip_dict[pattern_type][ip]["amount"] += 1
        if self.ip_dict[pattern_type][ip]["amount"] == self.settings["failed_attempts"]:
            if not self.database_connection.select(ip):
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
        self.ip_blacklisted = True
        with self.lock:
            self.database_connection.insert(ip)

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
        while True:
            if self.ip_blacklisted:
                print("Saving newly blacklisted IP's!")
                subprocess.call("iptables-save > Config/blacklist.v4", shell=True)
                self.ip_blacklisted = False
                time.sleep(300)

    def __setup_regex(self):
        self.regex = {}
        for key in self.ip_dict:
            self.regex[key] = []
            for regex in self.rules[key]["regex_patterns"]:
                if isinstance(regex, str):
                    self.regex[key].append(re.compile(regex))
                else:
                    regex = regex[0].format("|".join(self.rules[key][regex[1]]))
                    self.regex[key].append(re.compile(regex))

        self.ip_regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def __setup_database(self, data):
        if self.settings["database"] == "sqlite":
            self.database_connection = SqliteConnection(data["sqlite"])
        elif self.settings["database"] == "redis":
            self.database_connection = RedisConnection(data["redis"])
        else:
            raise DatabaseConfigException("Database has to be redis or sqlite!")

    def run(self):
        if self.settings["reload_iptables"]:
            if os.path.isfile("Config/blacklist.v4"):
                print("Updating firewall rules!")
                subprocess.call("iptables-restore < Config/blacklist.v4", shell=True)

        for key in self.rules:
            t = threading.Thread(target=self.read_files, args=(key,), name=key)
            t.daemon = True
            t.start()

        t = threading.Thread(target=self.make_persistent, name="persistent")
        t.daemon = True
        t.start()
