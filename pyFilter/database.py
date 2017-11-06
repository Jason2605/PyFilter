import sqlite3
try:
    from redis import Redis
except ImportError:
    Redis = None


class RedisConnection:
    """Rename the set/get to match sqlite, this will mean the methods are the same for either way of storage"""
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
        ip = "{}-pyFilter-{}".format(ip, self.name)
        self.redis_connection.set(ip, "Banned")

    def select(self, ip):
        ip_formatted = "{}-pyFilter-{}".format(ip, self.name)
        found = self.redis_connection.get(ip_formatted)
        if found:
            return found
        return self.redis_connection.get(ip)

    def scan(self):
        all_results = []
        cursor, results = self.redis_connection.scan(0, "*-pyFilter-[^\D{}]".format(self.name))
        all_results.extend(results)
        while cursor != 0:
            cursor, results = self.redis_connection.scan(cursor, "*-pyFilter-[^\D{}]".format(self.name))
            all_results.extend(results)
        return all_results

    def rename_keys(self, keys_formatted):
        keys = [x.split("-")[0] for x in keys_formatted]
        for index, key in enumerate(keys_formatted):
            self.redis_connection.rename(key, keys[index])


class SqliteConnection:
    def __init__(self, config):
        database = config["database"]
        self.sqlite_connection = sqlite3.connect(database, check_same_thread=False)
        cursor = self.sqlite_connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS banned_ip (ip text PRIMARY KEY)''')
        self.sqlite_connection.commit()
        cursor.close()

    def insert(self, ip):
        cursor = self.sqlite_connection.cursor()
        try:
            cursor.execute("INSERT INTO banned_ip VALUES (?)", (ip,))
            self.sqlite_connection.commit()
        except sqlite3.IntegrityError:
            print("IP already in the database")
        finally:
            cursor.close()

    def select(self, ip):
        cursor = self.sqlite_connection.cursor()
        cursor.execute("SELECT ip FROM banned_ip WHERE ip = ?", (ip,))
        ip = cursor.fetchone()
        cursor.close()
        return ip
