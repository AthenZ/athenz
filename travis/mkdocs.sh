#!/usr/bin/env bash

sudo apt-get install python-pip python-dev build-essential
sudo pip install --upgrade pip
sudo pip install 'mkdocs>=1.0.4'
sudo pip install pymarkdownlint mkdocs-material

mkdocs build --clean

ls -lh site/
