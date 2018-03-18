import sqlite3
import time
import socket
from datetime import datetime

try:
    from redis import Redis
except ImportError:
    Redis = None


class RedisConnection:
    """
    Rename the set/get methods to match sqlite,
    this will mean the methods are the same for either way of storage.

    Creates an object to interface with the redis key-value store

    Args:
        Dictionary passed from config.json
    """

    def __init__(self, config):
        if Redis is None:
            raise ImportError("Redis isn't installed!")
        self.redis_connection = Redis(db=config["database"],
                                      host=config["host"],
                                      password=config["password"],
                                      decode_responses=True)

        self.sync_active = config["sync_bans"]["active"]
        self.check_time = config["sync_bans"]["check_time"]
        self.name = config["sync_bans"]["name"]

        self.pub_sub = self.redis_connection.pubsub()
        self.pub_sub.subscribe("PyFilter")

    def insert(self, ip_address, log_msg, country=""):
        """
        Inserts IP addresses into Redis

        Args:
            ip_address: IP address as a string to be inserted into redis
            log_msg: Reason as to why the IP is banned
            country: Country of where the IP is from
        """

        self.redis_connection.lpush("latest_10_keys", "{} {}".format(ip_address, self.name))
        self.redis_connection.ltrim("latest_10_keys", 0, 9)

        data = {
            self.name: datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reason": log_msg,
            "banned_server": self.name
        }

        if country:
            data["country"] = country

        self.redis_connection.hmset(ip_address, data)

        self.redis_connection.publish("PyFilter", "{} {}".format(ip_address, self.name))

    def select(self, ip_address):
        """
        Return an IP address from Redis

        Args:
            ip_address: IP to select from Redis

        Returns:
            Returns 1 (integer) if IP address is found else None
        """

        return self.redis_connection.hget(ip_address, self.name)

    def get_bans(self):
        """
        Gets ips from Redis Pub/Sub to be banned, so it doesnt need to scan redis in its entirety

        Returns:
            Returns a list of all IPs not relating to the name of this "server".
        """

        bans = []

        while True:
            ban = self.pub_sub.get_message()

            if not ban:
                return bans

            if ban["type"] != "message":
                continue

            ban_data = ban["data"].split()
            if len(ban_data) != 2:
                ban_data[1] = " ".join(ban_data[1:])

            if ban_data[1] == self.name:
                continue

            server = self.redis_connection.hget(ban_data[0], "banned_server")
            time_banned = self.redis_connection.hget(ban_data[0], server)

            self.redis_connection.hset(ban_data[0], self.name, time_banned)

            bans.append(ban_data[:2])

    def scan(self):
        """
        Get a list of keys which do not have this server name within the key,
        this means the ban has not been synced to the server, therefore it can
        be synced after being gathered.

        Returns:
            Returns a list of all IPs not relating to the name of this "server".
        """
        now = time.time()

        pipe = self.redis_connection.pipeline()

        all_results = []
        ip_list = []
        for result in self.redis_connection.scan_iter():
            if not self.__check_ip(result):
                continue

            pipe.hget(result, self.name)
            ip_list.append(result)

        zipped = zip(pipe.execute(), ip_list)
        ret = [x[1] for x in zipped if x[0] is None]

        for result in ret:
            server = self.redis_connection.hget(result, "banned_server")
            time_banned = self.redis_connection.hget(result, server)

            self.redis_connection.hset(result, self.name, time_banned)
            all_results.append((server, result))

        print("Finished. Took {} seconds!".format(time.time() - now))
        return all_results

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


class SqliteConnection:
    """
    Creates an object to interface with sqlite

    Args:
        Dictionary passed from config.json
    """

    def __init__(self, config):
        database = config["database"]
        cursor = None

        try:
            self.sqlite_connection = sqlite3.connect(database, check_same_thread=False)
            cursor = self.sqlite_connection.cursor()
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS banned_ip (
                id INTEGER PRIMARY KEY,
                ip text,
                time_banned integer,
                server_name text,
                log_msg text,
                country text
                )"""
            )
            self.sqlite_connection.commit()
        except Exception as e:
            print("{}: {}".format(type(e).__name__, e))
        finally:
            if cursor is not None:
                cursor.close()

    def insert(self, ip_address, log_msg, country=""):
        """
        Inserts a row into sqlite

        Args:
            ip_address: IP address to be inserted into sqlite
            log_msg: Reason as to why the IP is banned
            country: Country of where the IP is from
        """
        cursor = None

        try:
            cursor = self.sqlite_connection.cursor()
            cursor.execute(
                "INSERT INTO banned_ip(ip, time_banned, server_name, log_msg, country) VALUES (?, ?, ?, ?, ?)",
                (ip_address, time.time(), "Server-1", log_msg, country)
            )

            self.sqlite_connection.commit()
        except sqlite3.IntegrityError:
            print("IP already in the database")
        finally:
            if cursor is not None:
                cursor.close()

    def select(self, ip_address):
        """
        Selects a row from sqlite

        Args:
            ip_address: IP address to select from sqlite

        Returns:
            Returns ip address as a string if found, else None is returned
        """

        cursor = None

        try:
            cursor = self.sqlite_connection.cursor()
            cursor.execute("SELECT ip FROM banned_ip WHERE ip = ?", (ip_address,))
            ip_address = cursor.fetchone()
            return ip_address
        except Exception as e:
            print("{}: {}".format(type(e).__name__, e))
        finally:
            if cursor is not None:
                cursor.close()
