## Overview
In this guide, you will be able to start a local ZMS server and do local ui development from your favorite IDE.

## Prerequisites

Docker, Make toolchain, Node 12+

## Steps

Checkout Athenz from GitHub

```shell
git clone https://github.com/AthenZ/athenz
```

`cd` into the docker directory

```shell
cd docker
```

Run following command to download ZMS & ZMS DB docker images, and set it up with meaningful defaults for local development

```shell
make prepare-ui-dev-env
```

!!! Note
    If you are using MacOS, then the script prints out a command at the end, which you can execute to add the generated self-signed certificate to your login keychain
    so that you can access Athenz UI in the browser without certificate warning.
    If you don't want to do that, please follow appropriate instructions for your workstation and / or browser so that you can access Athenz UI in the browser.

Now `cd` into the ui directory & run `npm install` to download UI dependencies 

```shell
cd ../ui
npm install
```

Once dependencies are downloaded, start the UI server using following 

```shell
sudo nodemon -r dotenv/config app.js
```

!!! Note
    `sudo` is required because UI is using privileged port 443.

If you don't have nodemon installed, you can install it using 

```shell
npm install nodemon -g
```

Access the UI at https://localhost. For your convenience, local set up uses a TestUserAuthority which accepts any username and password as far as it's a same string.
To look at a pre-created "athenz" domain during start up, login with "athenz-admin" as username and password.

Now you can keep the UI instance running in the terminal, make changes to the code using your IDE and UI dev server will reload with your changes.