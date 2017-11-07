#!/usr/bin/env bash

if ! [ -f "/etc/systemd/system/pyFilter.service" ]
then
    sudo python3 create_service.py
    sudo mv pyFilter.service /etc/systemd/system/pyFilter.service
    sudo chmod +x run.sh
    sudo systemctl daemon-reload
    sudo systemctl start pyFilter
    sudo systemctl enable pyFilter
    echo Service created and enabled, check the status of it by using \"sudo systemctl status pyFilter\"
else
    echo Service already created.
fi
