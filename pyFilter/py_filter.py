import json
import os
import re
import socket
import subprocess
import threading
import time

from datetime import datetime

from .exceptions import DatabaseConfigException
from .database import SqliteConnection, RedisConnection


class PyFilter(object):
    def __init__(self, file_path="Config/config.json"):
        with open(file_path) as config:
            data = json.load(config)

        self.settings = data["settings"]
        self.log_settings = data["logging"]
        self.rules = data["settings"]["rules"]

        self.lock = threading.Lock()

        self.ip_blacklisted = False

        self.ip_dict = {key: {} for key in self.rules}
        self.__setup_regex()
        self.__setup_database(data)

    def read_files(self, pattern_type="ssh"):
        """
        Reads the log files for the specified pattern

        Args:
            pattern_type: pattern_type is a string to select the rule from the config
        """

        log_file = self.rules[pattern_type]["log_file"]

        if not log_file:
            print("No file to check within rule: {}".format(pattern_type.title()))
            return

        print("Checking {} logs".format(pattern_type.title()))

        if not os.path.isfile(log_file):
            print("WARNING: file {} could not be found".format(log_file))
            return

        while True:
            inode = os.stat(log_file).st_ino
            with open(log_file) as f:
                while True:
                    where = f.tell()
                    line = f.readline()
                    if not line:
                        if self.settings["run_once"]:
                            return

                        if inode != os.stat(log_file).st_ino:
                            break

                        time.sleep(1)
                        f.seek(where)
                        continue

                    for regex_pattern in self.regex[pattern_type]:
                        found = regex_pattern.findall(line)

                        if not found:
                            continue

                        found = found[0]
                        self.filter(pattern_type, found)

                    time.sleep(0.0001)  # Ensure it doesnt kill CPU

    def filter(self, pattern_type, found):
        """
        Filters the IP addresses from HTTP verb (for nginx/apache) and
        checks if the IP address is within the allowed IP address list

        Args:
            pattern_type: A string to select the correct rule and ip
            found: A matching regex string
        """

        cond = pattern_type in ("apache", "nginx")

        ip = found[not cond]
        t = datetime.strptime(found[cond], self.rules[pattern_type]["time_format"])

        if cond and int(found[3]) not in self.settings[pattern_type]["http_status_blocks"]:
            return

        this_year = datetime.now().year

        if t.year != this_year:
            t = t.replace(year=this_year)

        if not self.ip_regex.match(ip):
            ip = socket.gethostbyname(ip)

        if ip not in self.settings["ignored_ips"]:
            if ip not in self.ip_dict[pattern_type]:
                self.ip_dict[pattern_type][ip] = {"amount": 0, "last_request": None}
            self.check(ip, pattern_type, t)

    def check(self, ip, pattern_type, time_object):
        """
        Checks if the last known request and current request are within the threshold limit for attempts being added
        and if so add an attempt.

        Args:
            ip: IP address as a string to be blacklisted if not already done so
            pattern_type: A string which selects the correct dictionary to get the amount of failed attempts for that IP
            time_object: A datetime object to check last request time
        """

        old_time_object = self.ip_dict[pattern_type][ip]["last_request"]

        self.ip_dict[pattern_type][ip]["last_request"] = time_object

        if old_time_object is None:
            return

        time_since_request = (time_object - old_time_object).total_seconds()
        if time_since_request > self.settings["request_time"]:
            return  # Returns if the last request was more than the specified time

        self.ip_dict[pattern_type][ip]["amount"] += 1

        if self.ip_dict[pattern_type][ip]["amount"] == self.settings["failed_attempts"]:

            if self.database_connection.select(ip):
                return

            self.blacklist(ip)

            if self.log_settings["active"]:
                log_msg = "IP: {} has been blacklisted and the firewall rules have been updated. "
                "Acquired 5 bad connections via {}.\n".format(ip, pattern_type)

                self.log(log_msg)
                print(log_msg, end='')

    def blacklist(self, ip, save=True):
        """
        Blacklists the IP address within iptables and save the IP to the chosen storage

        Args:
            ip: IP address as a string to be blacklisted
            save: Boolean to save the blacklisted IP address to the database
        """

        blacklist_string = "iptables -I INPUT -s {} -j {}".format(ip, self.settings["deny_type"])
        subprocess.call(blacklist_string.split())
        self.ip_blacklisted = True

        if not save:
            return

        with self.lock:
            self.database_connection.insert(ip)

    def log(self, log_message):
        """
        Create log files for when IP addresses are blacklisted

        Args:
            log_message: A string to be wrote to the logs
        """

        config_dir = self.log_settings["directory"]
        day_dir = "{}/{}".format(config_dir, datetime.now().strftime("%Y-%m-%d"))

        if not os.path.isdir(config_dir):
            os.mkdir(config_dir)

        if not os.path.isdir(day_dir):
            os.mkdir(day_dir)

        file_name = "{}/{}.log".format(day_dir, datetime.now().strftime("%Y-%m-%d %H"))
        with open(file_name, 'a' if os.path.isfile(file_name) else 'w') as file:
            file.write("{} {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), log_message))

    def make_persistent(self):
        """
        Saves blacklisted IP addresses using iptables-save which can be reloaded on start
        """

        while True:
            if self.ip_blacklisted:
                print("Saving newly blacklisted IP's!")
                subprocess.call("iptables-save > Config/blacklist.v4", shell=True)
                self.ip_blacklisted = False
                time.sleep(300)

    def monitor_redis(self):
        """
        Monitors redis for bans added from other pyFilter systems
        """

        while True:
            ip_list = self.database_connection.scan()
            if ip_list:
                for ip in ip_list:
                    ip_string = ip.split('-')
                    ip = ip_string[0]

                    if self.log_settings["active"]:
                        log_message = "Found IP: {} from server: {} - Blacklisting".format(ip, ip_string[2])
                        print(log_message)
                        self.log(log_message)

                    self.blacklist(ip, False)
                self.database_connection.rename_keys(ip_list)
            time.sleep(self.database_connection.check_time)

    def __setup_regex(self):
        """
        Sets up the needed regex patterns
        """

        self.regex = {}
        for key in self.ip_dict:
            self.regex[key] = []
            for regex in self.rules[key]["regex_patterns"]:
                if not isinstance(regex, str):
                    regex = regex[0].format("|".join(self.rules[key][regex[1]]))
                self.regex[key].append(re.compile(regex))

        self.ip_regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def __setup_database(self, data):
        """
        Sets up the database object needed for pyFilter

        Args:
            data: A dictionary passed from config.json storing details for the chosen storage method
        """

        if self.settings["database"] == "sqlite":
            self.database_connection = SqliteConnection(data["sqlite"])
        elif self.settings["database"] == "redis":
            self.database_connection = RedisConnection(data["redis"])
        else:
            raise DatabaseConfigException("Database has to be redis or sqlite!")

    def run(self):
        """
        Creates the threads needed for pyFilter to run. This method starts pyFilter.
        """

        if self.settings["reload_iptables"]:
            if os.path.isfile("Config/blacklist.v4"):
                print("Updating firewall rules!")
                subprocess.call("iptables-restore < Config/blacklist.v4", shell=True)

        threads = []

        for key in self.rules:
            threads.append(threading.Thread(target=self.read_files, args=(key,), name=key))

        threads.append(threading.Thread(target=self.make_persistent, name="persistent"))

        for t in threads:
            t.daemon = True
            t.start()

        if self.settings["database"] == "redis":
            if self.database_connection.sync_active:
                self.monitor_redis()
        threads[0].join()  # Keeps main thread open if redis monitoring isnt enabled
