import sqlite3
import time
from datetime import datetime
try:
    from redis import Redis
except ImportError:
    Redis = None


class RedisConnection:
    """
    Rename the set/get to match sqlite, this will mean the methods are the same for either way of storage.

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
                                      decode_responses=True
                                      )
        self.sync_active = config["sync_bans"]["active"]
        self.check_time = config["sync_bans"]["check_time"]
        self.name = config["sync_bans"]["name"]

        self.pub_sub = self.redis_connection.pubsub()
        self.pub_sub.subscribe("PyFilter")

    def insert(self, ip, log_msg):
        """
        Inserts IP addresses into Redis

        Args:
            ip: IP address as a string to be inserted into redis
            log_msg: Reason as to why the IP is banned
        """

        self.redis_connection.lpush("latest_10_keys", "{} {}".format(ip, self.name))
        self.redis_connection.ltrim("latest_10_keys", 0, 9)

        self.redis_connection.hmset(ip, {
            self.name: datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reason": log_msg,
            "banned_server": self.name
        })

        self.redis_connection.publish("PyFilter", "{} {}".format(ip, self.name))

    def select(self, ip):
        """
        Return an IP address from Redis

        Args:
            ip: IP to select from Redis

        Returns:
            Returns 1 (integer) if IP address is found else None
        """

        return self.redis_connection.hget(ip, self.name)

    def get_bans(self):
        """
        Gets ips from Redis Pub/Sub to be banned, so it doesnt need to scan redis in its entirety

        Returns:
            Returns a list of all IPs not relating to the name of this "server" from the passed config
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
            Returns a list of all IPs not relating to the name of this "server" from the passed config
        """

        all_results = []
        for result in self.redis_connection.scan_iter():
            if self.redis_connection.type(result) != "hash":
                continue

            keys = self.redis_connection.hkeys(result)
            if self.name in keys:
                continue

            server = self.redis_connection.hget(result, "banned_server")
            time_banned = self.redis_connection.hget(result, server)

            self.redis_connection.hset(result, self.name, time_banned)
            all_results.append((server, result))

        return all_results


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
                log_msg text
                )"""
            )
            self.sqlite_connection.commit()
        except Exception as e:
            print("{}: {}".format(type(e).__name__, e))
        finally:
            if cursor is not None:
                cursor.close()

    def insert(self, ip, log_msg):
        """
        Inserts a row into sqlite

        Args:
            ip: IP address to be inserted into sqlite
        """

        cursor = self.sqlite_connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO banned_ip(ip, time_banned, server_name, log_msg) VALUES (?, ?, ?, ?)",
                (ip, time.time(), "Server-1", log_msg)
            )

            self.sqlite_connection.commit()
        except sqlite3.IntegrityError:
            print("IP already in the database")
        finally:
            cursor.close()

    def select(self, ip):
        """
        Selects a row from sqlite

        Args:
            ip: IP address to select from sqlite

        Returns:
            Returns ip address as a string if found, else None is returned
        """
        cursor = None
        
        try:
            cursor = self.sqlite_connection.cursor()
            cursor.execute("SELECT ip FROM banned_ip WHERE ip = ?", (ip,))
            ip = cursor.fetchone()
            return ip
        except Exception as e:
            print("{}: {}".format(type(e).__name__, e))
        finally:
            if cursor is not None:
                cursor.close()
