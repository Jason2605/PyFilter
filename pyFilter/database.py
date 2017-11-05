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
        self.redis_connection = Redis(db=config["database"], host=config["host"], password=config["password"])

    def insert(self, ip):
        self.redis_connection.set(ip, "Banned")

    def select(self, ip):
        return self.redis_connection.get(ip)


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
