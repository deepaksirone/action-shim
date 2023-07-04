#!/bin/bash

set -ex

sudo apt update
sudo apt install -y python3-pip python3.7 python-dev python3-dev libpython3.7-dev build-essential cargo
python3.7 -m pip install --upgrade pip
python3.7 -m pip install -r requirements.txt
