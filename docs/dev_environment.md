# Development Environment

* [Development Tools](#development-tools)
  * [CI Build Environment](#ci-build-environment)
  * [Manual Installation of Development Tools](#manual-installation-of-development-tools)
      * [Java Platform JDK 17](#java-platform-jdk-17)
      * [Maven](#maven)
      * [Git Client](#git-client)
      * [Go](#go)
      * [Node JS](#node-js)
      * [Docker](#docker)
* [Build Steps](#build-steps)

## Development Tools

If you would like to build your own copy of Athenz rather than
using the pre-built binary packages, then here is the list of
development tools you need to have installed on your system.

### CI Build Environment

Athenz packages are built and released using GitHub Actions. The
workflow files in the [.github/workflows](https://github.com/AthenZ/athenz/tree/master/.github/workflows)
directory (e.g. [pull-request.yaml](https://github.com/AthenZ/athenz/blob/master/.github/workflows/pull-request.yaml))
are the authoritative reference for the versions of the development
tools used to build and test Athenz.

### Manual Installation of Development Tools

#### Java Platform JDK 17

To build Athenz components, you must have Java Platform JDK 17 installed
on your machine. The main authorization services - ZMS and ZTS, are
written in Java and using embedded Jetty 12, which requires JDK 17.
The client libraries are still compiled for and supported on JDK 11.

Make sure you have set the $JAVA_HOME environment variable.

```shell
$ java -XshowSettings:properties -version 2>&1 > /dev/null | grep 'java.home'
$ export JAVA_HOME=<java-home-directory>
````

#### Maven

Download and install [Apache Maven](http://maven.apache.org/download.cgi).

#### Git Client

If you don't have git client installed on your host, you can download
one from [Git website](https://git-scm.com/downloads). 2.x version of
the git client is required.

#### Go

Install go 1.24.2 or newer version by following the directions at
[Getting Started - The Go Programming Language](https://golang.org/doc/install).

Make sure you have set the [$GOPATH environment variable](https://pkg.go.dev/cmd/go#hdr-GOPATH_environment_variable)
and that you have `$GOPATH/bin` in your `$PATH`.

```shell
$ export GOPATH=<gopath-directory>
$ mkdir -p $GOPATH/bin
$ export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
````

#### Node JS

Install node 22.x by following the directions at
[Node.js JavaScript Runtime](https://nodejs.org/en/)

Verify that you have the required minimum version of `node`,
`npm` and `nodemon` binaries installed on your system and are included
in your runtime path:

```shell
$ node --version
v22.15.1
$ npm -v
10.9.2
$ npm install -g nodemon
$ nodemon --version
3.0.3
```

#### Docker

The ZMS server unit tests start a MySQL server using
[Testcontainers](https://testcontainers.com/), so you must have
[Docker](https://docs.docker.com/get-docker/) installed and running
on your machine to run the full build including the tests. The tests
use the `mysql/mysql-server:8.0` image by default. You can use a different
MySQL image by setting the `ZMS_TEST_MYSQL_IMAGE` environment variable.

## Build Steps

To build Athenz components, change to the top level directory where
you want to build the Athenz code and execute (skip the first command
if you have already checked out the code using git):

```shell
$ git clone https://github.com/AthenZ/athenz.git
$ cd athenz
$ mvn clean install
```

The release packages will be created automatically in the `assembly`
subdirectory.
