#!/usr/bin/env bash

if ! [ -f "/etc/systemd/system/PyFilter.service" ]
then
    sudo python3 create_service.py
    sudo mv PyFilter.service /etc/systemd/system/PyFilter.service
    sudo chmod +x run.sh
    sudo systemctl daemon-reload
    sudo systemctl start PyFilter
    sudo systemctl enable PyFilter
    echo Service created and enabled, check the status of it by using \"sudo systemctl status PyFilter\"
else
    echo Service already created.
    echo Check the status of it by using \"sudo systemctl status PyFilter\"
fi
