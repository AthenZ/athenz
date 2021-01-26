#!/usr/bin/env bash

apt-get install python-pip python-dev build-essential
pip install --upgrade pip
pip install 'mkdocs>=1.0.4'
pip install pymarkdownlint mkdocs-material

mkdocs build --clean

ls -lh site/
