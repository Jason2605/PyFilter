import json
import os
import re
import socket
import subprocess
import threading
import time
import glob

try:
    import geoip2.database
except Exception:
    geoip2 = None

from datetime import datetime

from .exceptions import DatabaseConfigException
from .database import SqliteConnection, RedisConnection


class PyFilter(object):
    def __init__(self, file_path="Config/config.json"):
        with open(file_path, "r") as config:
            data = json.load(config)

        self.settings = data["settings"]
        self.log_settings = data["logging"]
        self.rules = data["settings"]["rules"]

        self.lock = threading.Lock()

        self.ip_blacklisted = False

        self.ip_dict = {key: {} for key in self.rules}
        self.__setup_regex()
        self.__setup_database(data)

        if geoip2 is not None:
            self.reader = geoip2.database.Reader("GeoLite2-Country.mmdb")

    def read_files(self, log_file, pattern_type="ssh"):
        """
        Reads the log files for the specified regex pattern

        Args:
            log_file: log file to be read and monitored
            pattern_type: pattern_type is a string to select the rule from the config
        """

        print("Checking {} logs".format(pattern_type.title()))

        while True:
            inode = os.stat(log_file).st_ino
            with open(log_file, "r") as f:
                while True:
                    where = f.tell()
                    line = f.readline()
                    if not line:

                        if inode != os.stat(log_file).st_ino:
                            break

                        time.sleep(1)
                        f.seek(where)
                        continue

                    for regex_pattern in self.regex[pattern_type]:
                        found = regex_pattern[0].findall(line)

                        if found:
                            self.filter(pattern_type, found[0], regex_pattern[1])

                    time.sleep(0.0001)  # Ensure it doesnt kill CPU

    def filter(self, pattern_type, found, instant_ban):
        """
        Filters the IP addresses from HTTP verb (for nginx/apache) and
        checks if the IP address is within the allowed IP address list

        Args:
            pattern_type: A string to select the correct rule and ip
            found: A matching regex string
            instant_ban: Boolean passed to instantly ban the IP on a certain regex match
        """

        cond = pattern_type in ("apache", "nginx")

        ip_address = found[not cond]
        time_obj = datetime.strptime(found[cond], self.rules[pattern_type]["time_format"])

        if cond and int(found[3]) not in self.rules[pattern_type]["http_status_blocks"]:
            return

        this_year = datetime.now().year

        if time_obj.year != this_year:
            time_obj = time_obj.replace(year=this_year)  # Assume the request was this year

        ip_type = self.__check_ip(ip_address)

        if not ip_type:
            ip_address = socket.gethostbyname(ip_address)
            ip_type = self.__check_ip(ip_address)

        if ip_address not in self.settings["ignored_ips"]:
            if instant_ban:
                if self.database_connection.select(ip_address) is not None:
                    return

                country = ""
                country_log = ""

                if geoip2 is not None:
                    try:
                        country = self.reader.country(ip_address).country.name
                    except geoip2.errors.AddressNotFoundError:
                        country = "unknown!"

                    country_log = "The IP was from {}.".format(
                        country
                    )

                log_msg = "IP: {} has been blacklisted and the firewall rules have been updated." \
                          " Acquired an instant ban via {}. {}\n".format(ip_address, pattern_type, country_log)

                if self.log_settings["active"]:
                    self.log(log_msg)
                    print(log_msg, end='')

                return self.blacklist(ip_address, log_msg=log_msg, ip_type=ip_type, country=country)

            if ip_address not in self.ip_dict[pattern_type]:
                self.ip_dict[pattern_type][ip_address] = {"amount": 0, "last_request": None}
            self.check(ip_address, pattern_type, time_obj, ip_type)

    def check(self, ip_address, pattern_type, time_object, ip_type="v4"):
        """
        Checks if the last known request and current request are within the
        threshold limit for attempts being added and if so add an attempt.

        Args:
            ip_address: IP address as a string to be blacklisted if not already done so
            pattern_type: A string which selects the correct dictionary to get the
                          amount of failed attempts for that IP
            time_object: A datetime object to check last request time
            ip_type: Differentiates between the v4 and v6 protocols
        """

        old_time_object = self.ip_dict[pattern_type][ip_address]["last_request"]

        self.ip_dict[pattern_type][ip_address]["last_request"] = time_object

        if old_time_object is None:
            return

        time_since_request = (time_object - old_time_object).total_seconds()
        if time_since_request > self.settings["request_time"]:
            return  # Returns if the last request was more than the specified time

        self.ip_dict[pattern_type][ip_address]["amount"] += 1

        if self.ip_dict[pattern_type][ip_address]["amount"] == self.settings["failed_attempts"]:

            if self.database_connection.select(ip_address) is not None:
                return

            country = ""
            country_log = ""

            if geoip2 is not None:
                try:
                    country = self.reader.country(ip_address).country.name
                except geoip2.errors.AddressNotFoundError:
                    country = "unknown!"
                country_log = "The IP was from {}.".format(
                    country
                )

            log_msg = "IP: {} has been blacklisted and the firewall rules have been updated." \
                      " Acquired 5 bad connections via {}. {}\n".format(ip_address, pattern_type, country_log)

            if self.log_settings["active"]:
                self.log(log_msg)
                print(log_msg, end='')

            try:
                del self.ip_dict[pattern_type][ip_address]  # Remove blacklisted IP
            except KeyError:
                pass

            self.blacklist(ip_address, log_msg=log_msg, ip_type=ip_type, country=country)

    def blacklist(self, ip_address, save=True, log_msg="Unknown", ip_type="v4", country=""):
        """
        Blacklists the IP address within iptables and save the IP to the chosen storage

        Args:
            ip_address: IP address as a string to be blacklisted
            save: Boolean to save the blacklisted IP address to the database
            log_msg: Reason as to why the IP has been banned
            ip_type: Differentiates between the v4 and v6 protocols
            country: Country of where the IP is from
        """

        iptables_type = "iptables" if ip_type == "v4" else "ip6tables"

        blacklist_string = "{} -I INPUT -s {} -j {}".format(
            iptables_type, ip_address, self.settings["deny_type"]
        )
        subprocess.call(blacklist_string.split())
        self.ip_blacklisted = True

        if not save:
            return

        with self.lock:
            self.database_connection.insert(ip_address, log_msg, country)

    def log(self, log_message):
        """
        Create log files for when IP addresses are blacklisted

        Args:
            log_message: A string to be wrote to the logs
        """

        log_directory = self.log_settings["directory"]
        month_dir = "{}/{}".format(log_directory, datetime.now().strftime("%Y-%b"))
        day_dir = "{}/{}".format(month_dir, datetime.now().strftime("%Y-%m-%d"))

        for directory in (log_directory, month_dir, day_dir):
            if not os.path.isdir(directory):
                os.mkdir(directory)

        file_name = "{}/{}.log".format(day_dir, datetime.now().strftime("%Y-%m-%d %H"))
        with open(file_name, 'a' if os.path.isfile(file_name) else 'w') as file:
            file.write("{} {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), log_message))

    def make_persistent(self, loop=True):
        """
        Saves blacklisted IP addresses using iptables-save which can be reloaded on start
        """

        while True:
            if self.ip_blacklisted:
                print("Saving newly blacklisted IP's!")
                for extension, command in (("v4", "iptables-save"), ("v6", "ip6tables-save")):
                    with open("Config/blacklist.{}".format(extension), "w") as f:
                        subprocess.call([command], stdout=f)
                self.ip_blacklisted = False

            if not loop:
                return

            time.sleep(300)

    def monitor_redis(self):
        """
        Monitors redis for bans added from other PyFilter systems
        """

        self.check_redis()

        while True:
            for ip_address, server_name in self.database_connection.get_bans():
                self.__redis_ban(server_name, ip_address)

            time.sleep(self.database_connection.check_time)

    def check_redis(self):
        """
        Checks all previous bans and adds them on startup
        """

        for server_name, ip_address in self.database_connection.scan():
            self.__redis_ban(server_name, ip_address)

    def __redis_ban(self, server_name, ip_address):
        """
        Function to ban/log IP's found via redis

        Args:
            server_name: Name of the server which banned the IP
            ip_address: IP to be banned
        """

        if self.log_settings["active"]:

            country_log = ""

            if geoip2 is not None:
                try:
                    country = self.reader.country(ip_address).country.name
                except geoip2.errors.AddressNotFoundError:
                    country = "unknown!"

                country_log = "The IP was from {}.".format(
                    country
                )

            log_message = "Found IP: {} from server: {} - Blacklisting. {}\n".format(
                ip_address, server_name, country_log
            )
            print(log_message, end="")
            self.log(log_message)

        ip_type = self.__check_ip(ip_address)
        self.blacklist(ip_address, False, ip_type=ip_type)

    def __setup_regex(self):
        """
        Sets up the needed regex patterns
        """

        self.regex = {}
        for key in self.ip_dict:
            self.regex[key] = []
            for regex in self.rules[key]["regex_patterns"]:
                instant_ban = False
                if not isinstance(regex, str):
                    if isinstance(regex[1], str):
                        regex = regex[0].format("|".join(self.rules[key][regex[1]]))
                    elif isinstance(regex[1], bool):
                        regex = regex[0]
                        instant_ban = True
                self.regex[key].append([re.compile(regex), instant_ban])

    def __setup_database(self, data):
        """
        Sets up the database object needed for PyFilter

        Args:
            data: A dictionary passed from config.json storing details for the chosen storage method
        """

        if self.settings["database"] == "sqlite":
            self.database_connection = SqliteConnection(data["sqlite"])
        elif self.settings["database"] == "redis":
            self.database_connection = RedisConnection(data["redis"])
        else:
            raise DatabaseConfigException("Database has to be redis or sqlite!")

    def __check_ip(self, ip_address, last=False):
        """
        Checks to see if the given IP is v4 or v6

        Args:
            ip_address: The ip string to be checked
            last: A base case to stop recursion

        Returns:
            If IP is matched as either v4 or v6 a string is returned, else False
        """
        ip_type = (socket.AF_INET, "v4") if not last else (socket.AF_INET6, "v6")
        try:
            socket.inet_pton(ip_type[0], ip_address)
            return ip_type[1]
        except OSError:
            if last:
                return False
            return self.__check_ip(ip_address, True)

    def run(self):
        """
        Creates the threads needed for PyFilter to run. This method starts PyFilter.
        """

        if self.settings["reload_iptables"]:
            for extension, command in (("v4", "iptables-restore"), ("v6", "ip6tables-restore")):
                ip_file = "Config/blacklist.{}".format(extension)
                if not os.path.isfile(ip_file):
                    continue
                print("Updating firewall rules ({})!".format(extension))
                with open(ip_file) as f:
                    subprocess.call([command], stdin=f)

        threads = []

        for key in self.rules:
            log_files_pattern = self.rules[key]["log_files"]

            if not log_files_pattern:
                print("No log files pattern to check within rule: {}".format(key.title()))
                continue

            for log_file in glob.glob(log_files_pattern):
                if not os.path.isfile(log_file):
                    print("WARNING: file {} could not be found".format(log_file))
                    continue

                threads.append(threading.Thread(target=self.read_files, args=(log_file, key), name=key))

        threads.append(threading.Thread(target=self.make_persistent, name="persistent"))

        for thread in threads:
            thread.daemon = True
            thread.start()

        if self.settings["database"] == "redis":
            if self.database_connection.sync_active:
                self.monitor_redis()
        threads[0].join()  # Keeps main thread open if redis monitoring isn't enabled
