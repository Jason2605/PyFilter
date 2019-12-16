<p align="center">
  <a href="https://pyfilter.co.uk" target="_blank"><img src="https://pyfilter.co.uk/static/images/Shield.png" width="200"/></a>
</p>

# PyFilter
PyFilter aims to filter out all of the requests that are not legitimate to your server, and blocks them if too many are sent. It works by reading log files and checking if a failed request has came from the same IP address within a user configurable amount of time and adding rules to the firewall if too many attempts have been captured.

By default PyFilter is configured to read from `/var/log/auth.log` for incoming SSH requests, however there are options for `Apache, Nginx and MySQL` too.

PyFilter uses a database to store all the banned ip addresses to ensure ips arent added more than once. PyFilter currently supports sqlite and redis, by default it is setup to use sqlite so no installation of a redis server is needed. However redis has support for cross server ban syncing (more info below).

Installation:
-------------

Required:
- [Python3](http://www.python.org)

Optional:
- [py-redis](https://pypi.python.org/pypi/redis)
- [redis](https://redis.io)
- [geoip2](https://geoip2.readthedocs.io/en/latest/)

To install PyFilter download the files from this repo via your preferred method, for example `git clone https://github.com/Jason2605/PyFilter.git`.

**Optional:** `install.sh` will setup a service for PyFilter, and you can start/stop it by using `sudo systemctl start/stop PyFilter` and get the status of the PyFilter service using `sudo systemctl status PyFilter`. To run this make sure you give permission to the `install.sh` file `sudo chmod +x install.sh`.

**Note: The default configuration file runs on sqlite, so installing py-redis and redis are optional.**

To install py-redis
  `pip install redis`
  
To install redis (debian)
[Tutorial](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-redis)
   ```
   sudo apt-get update
   sudo apt-get install build-essential
   sudo apt-get install tcl8.5
   wget http://download.redis.io/releases/redis-stable.tar.gz
   tar xzf redis-stable.tar.gz
   cd redis-stable
   make
   make test
   sudo make install
   cd utils
   sudo ./install_server.sh
   ```
   
Starting/stopping redis
  ```
  sudo service redis_6379 start
  sudo service redis_6379 stop
  ```
  
**Optional** Geoip2 will provide the country of the banned ip address.
To install geopip2
  `pip install geoip2`
  
Configuration:
-------------

- Copy the [default config file](https://github.com/Jason2605/PyFilter/blob/master/Config/config.default.json) and call it config.json.
```json
{
  "settings": {
    "database": "sqlite",
    "failed_attempts": 5,
    "deny_type": "DROP",
    "ignored_ips": ["127.0.0.1"],
    "request_time": 5,
    "reload_iptables": true,
    "rules": {
      "ssh": {
        "log_files": "/var/log/auth.log",
        "regex_patterns": [
          "([a-zA-Z]{3}\\s+\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}).* Invalid user .* from (.*) port (.*)",
          "([a-zA-Z]{3}\\s+\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}).* Failed password for .* from (.*) port (.*)",
          "([a-zA-Z]{3}\\s+\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}).* Did not receive identification string from (.*) port (.*)",
          "([a-zA-Z]{3}\\s+\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}).* Received disconnect from (.*) port (.*):\\d{0,4}: .*",
          "([a-zA-Z]{3}\\s+\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}).* Unable to negotiate with (.*) port .*",
          ["([a-zA-Z]{3}\\s+\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}).* error: maximum authentication attempts exceeded for .* from (.*) port .*", true]
        ],
        "time_format": "%b %d %H:%M:%S"
      },
      "mysql": {
        "log_files": "",
        "regex_patterns": [
          "(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) .* Access denied for user '.*'@'(.*)' .*"
        ],
        "time_format": "%Y-%m-%d  %H:%M:%S"
      },
      "apache": {
        "log_files": "",
        "regex_patterns": [
          ["(.*) .* .* \\[(.*) \\+0000\\] \"POST ({}) HTTP/1\\.1\" .*", "urls"]
        ],
        "time_format": "%d/%b/%Y:%H:%M:%S",
        "urls": ["/login/", "/admin/"],
        "http_status_blocks": [200]
      },
      "nginx": {
        "log_files": "",
        "regex_patterns": [
          ["(.*) .* .* \\[(.*) \\+0000\\] \"POST ({}) HTTP/1\\.1\" .*", "urls"]
        ],
        "time_format": "%d/%b/%Y:%H:%M:%S",
        "urls": ["/login/", "/admin/"],
        "http_status_blocks": [405]
      }
    }
  },
  "sqlite": {
    "database": "PyFilter.db"
  },
  "redis": {
    "host": "127.0.0.1",
    "password": null,
    "database": 0,
    "sync_bans": {
      "active": true,
      "name": "1",
      "check_time": 600
    }
  },
  "logging": {
    "active": true,
    "directory": "Logs"
  }
}
```
To add more rules just add another section.
```json
      "mariadb": {
        "log_files": ["/var/log/x"],
        "regex_patterns": [
          "(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) .* Access denied for user '.*'@'(.*)' .*"
        ],
        "time_format": "%Y-%m-%d  %H:%M:%S"
      },
```
### Database

To swap from sqlite to redis, change the current value `"database": "sqlite"` to `"database": "redis"`.

### Reload iptables

`iptables` is not persistent over restarts, so this setting will reload the table with the saved bans so far on launch and update the rules.

### Log files

`"log_files": "/var/log/auth.log"` OR `"log_files": "/var/log/*.log"` This will read from the specified file, or specified pattern of files, and add bans as the events happen. See allowed glob patterns [here.](https://docs.python.org/3/library/fnmatch.html#fnmatch.fnmatch)

### Regex patterns

The regex patterns **have** to match an IP address and a timestamp, preferably matching the timestamp first. If you have a regex pattern you wish to instantly ban on, wrap the pattern with [] and add `, true`. 
For example 
```
["([a-zA-Z]{3}\\s+\\d{1,2} \\d{1,2}:\\d{1,2}:\\d{1,2}).* error: maximum authentication attempts exceeded for .* from (.*) port .*", true]
```

### Time format

The time format needs to match the log format to form a datetime object. For example `2017-10-30 13:37:11` will match with `%Y-%m-%d  %H:%M:%S`.

#### Some common characters
```
%Y -> Year
%m -> Month (Month as number form e.g 10 = October)
%b -> Month (Month as abbreviated name e.g Oct)
%B -> Month (Month as full name e.g October)
%d -> Day
%H -> Hour
%S -> Second
%d -> Day within a month (e.g 1 for 1st of the month)
```
[Full list](https://docs.python.org/3/library/datetime.html#strftime-strptime-behavior)

### Ignored IP addresses

This is quite explanatory, if a regex matches however the IP address is within this list, it will be ignored so that IP address will not get banned.

You can add more IPs
`"ignored_ips": ["127.0.0.1", "123.456.789.1"]`

### Request time

Request time, is the time **in seconds** the responses have to be sent, so for example `"request_time": 5` if two requests are sent within 5 seconds of each other, that will add an attempt to that IP address, if that happens 5 times they will be blacklisted and added to the firewall rules. 

### Deny type

Deny type is the way iptables will deal with the incoming packets, `DENY` is recommended however you may also `REJECT` them.

### Failed attempts

Failed attempts is the number of matches that IP address needs to get trying to connect each rule for it to get blacklisted, for example `"failed_attempts": 5` 5 failed attempts on an SSH connection will get it banned, however 3 on SSH and 2 on MySQL will not get it banned, they are separate.

### Redis - Optional

Host is the ip address of where the redis server is located. The `"database"` option is the database you want the banned IP addresses to be stored in, by default within redis the options are 0 to 15. If you have a password for your redis server change `"password": null` to `"password": "your password"`.

Cross server ban syncing:
-------------------------

Cross server ban syncing allows IP addresses to be banned across multiple servers if this is enabled. For example if IP address X was banned on server Y, and server Z has ban syncing enabled it will blacklist that IP even if that IP has not met the required failed attempts on **that** server.

```json
    "sync_bans": {
      "active": true,
      "name": "1",
      "check_time": 600
    }
```
This is the section for ban syncing.

### Active

Enables/disables cross server ban syncing.

### Name

This is the name of the server, this **has** to be different for each server running PyFilter or the bans will not get synced properly. This name can be anything as long as it is unique, for example `"name": "VPS-Lon-1"`.

### Check time

The amount of time in seconds the redis server will be polled to check for new bans, and sync them.

Running:
--------
Note: To run this you will need sudo privileges, and will need to ensure the bash files have correct permissions. If not grant using `sudo chmod +x run.sh`.
```
$ ./run.sh
```

Sponsors:
--------
<a href="https://www.digitalocean.com"><img src="https://pyfilter.co.uk/static/images/DO_Logo_Vertical_Blue.png" width="100" height="100"/></a>
