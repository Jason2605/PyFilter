import os

cwd = os.getcwd()

service_text = """
[Unit]
Description=PyFilter
After=network.target

[Service]
WorkingDirectory={}
ExecStart={}/run.sh

[Install]
WantedBy=multi-user.target
""".format(cwd, cwd)


with open("PyFilter.service", 'w') as f:
    f.write(service_text)

