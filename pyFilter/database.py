import sqlite3
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

    def insert(self, ip):
        """
        Inserts IP addresses into Redis

        Args:
            ip: IP address to be inserted into redis
        """
        ip = "{}-pyFilter-{}".format(ip, self.name)
        self.redis_connection.set(ip, "Banned")

    def select(self, ip):
        """
        Return an IP address from Redis

        Args:
            ip: IP to select from Redis

        Returns:
            Returns the IP address as a string if found, else returns None
        """
        ip_formatted = "{}-pyFilter-{}".format(ip, self.name)
        found = self.redis_connection.get(ip_formatted)
        if found:
            return found
        return self.redis_connection.get(ip)

    def scan(self):
        """
        Get a list of keys matching a certain pattern using Redis scan

        Returns:
            Returns a list of all IPs not relating to the name of this object from the passed config
        """
        all_results = []
        cursor, results = self.redis_connection.scan(0, "*-pyFilter-[^\D{}]".format(self.name))
        all_results.extend(results)
        while cursor != 0:
            cursor, results = self.redis_connection.scan(cursor, "*-pyFilter-[^\D{}]".format(self.name))
            all_results.extend(results)
        return all_results

    def rename_keys(self, keys_formatted):
        """
        Renames the keys once it has been synced

        Args:
            keys_formatted: A list of formatted redis keys

        Renames keys such as x.x.x.x-pyFilter-1 to just x.x.x.x once the ban has been synced
        """
        keys = [x.split("-")[0] for x in keys_formatted]
        for index, key in enumerate(keys_formatted):
            self.redis_connection.rename(key, keys[index])


class SqliteConnection:
    """
    Creates an object to interface with sqlite

    Args:
        Dictionary passed from config.json
    """
    def __init__(self, config):
        database = config["database"]
        self.sqlite_connection = sqlite3.connect(database, check_same_thread=False)
        cursor = self.sqlite_connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS banned_ip (ip text PRIMARY KEY)''')
        self.sqlite_connection.commit()
        cursor.close()

    def insert(self, ip):
        """
        Inserts a row into sqlite

        Args:
            ip: IP address to be inserted into sqlite
        """
        cursor = self.sqlite_connection.cursor()
        try:
            cursor.execute("INSERT INTO banned_ip VALUES (?)", (ip,))
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
        cursor = self.sqlite_connection.cursor()
        cursor.execute("SELECT ip FROM banned_ip WHERE ip = ?", (ip,))
        ip = cursor.fetchone()
        cursor.close()
        return ip
