#!/bin/bash

sudo apt-get install python3-virtualenv
virtualenv --python=/usr/bin/python3.7 .
source bin/activate
pip install -r requirements.txt
