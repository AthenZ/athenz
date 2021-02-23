## Overview
In this introduction to Athenz, you will be able to run Athenz on your workstation.

## Prerequisites
* Docker
* Git
* Make toolset

## Steps

Checkout Athenz from Github
```shell
git clone https://github.com/AthenZ/athenz.git
```
`cd` to checked out directory and run following command:
```shell
cd athenz && ./start-local-athenz.sh
```
   
This script will -
   
- download Athenz components docker images from DockerHub
- generate self-signed certificates to be used by Athenz components
- configure Athenz with meaningful defaults suitable for local environment ( for production set up, please refer to "Production set up" section of docs.)
- start local containers corresponding to Athenz components (ZMS, ZMS DB, ZTS, ZTS DB, UI)

!!! Note 
    If you are using MacOS, then the script prints out a command at the end, which you can execute to add the generated self-signed certificate to your login keychain
    so that you can access Athenz UI in the browser without certificate warning.
    If you don't want to do that, please follow appropriate instructions for your workstation and / or browser so that you can access Athenz UI in the browser.

Access the UI at https://localhost. For your convenience local set up uses a TestUserAuthority which accepts any username and password as far as it's a same string. 
To look at a pre-created "athenz" domain during start up, login with "athenz-admin" as username and password.


