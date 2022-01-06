## Overview
In this guide, you will be able to start a local ZMS server and do local ui development from your favorite IDE.

## Prerequisites

Docker, Make toolchain, Node v14.x, nodemon v2.x

## Steps

Checkout Athenz from GitHub

```shell
git clone https://github.com/AthenZ/athenz
```

`cd` into the docker directory

```shell
cd docker
```

Run following command to download ZMS & ZMS DB docker images, and set it up with meaningful
defaults for local development:

```shell
make prepare-ui-dev-env
```

!!! Note
    If you are using macOS, then the script prints out a command at the end, which you can execute
    to add the generated self-signed certificate to your login keychain
    so that you can access Athenz UI in the browser without certificate warning.
    If you don't want to do that, please follow appropriate instructions for your workstation
    and / or browser so that you can access Athenz UI in the browser.

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

Access the UI at https://localhost. For your convenience, local set up uses a TestUserAuthority
which accepts any username and password as far as it's a same string. To look at a pre-created
"athenz" domain during start up, login with "athenz-admin" as username and password.

Now you can keep the UI instance running in the terminal, make changes to the code using your
IDE and UI dev server will reload with your changes.

## Troubleshooting

### Clean old artifacts

It is possible for build to fail if Athenz was previously built. To clean old artifacts run:
`./stop-local-athenz.sh`

### Certificate not trusted error when opening https://localhost

When you open https://localhost you might get a certificate error as the self-signed certificate isn't trusted.
To fix it, please follow the steps in [Accessing UI](https://github.com/AthenZ/athenz/blob/master/docs/setup_ui.md#ui-access)