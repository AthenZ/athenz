# Development Environment

* [Development Tools](#development-tools)
  * [Build Within Docker Container](#build-within-docker-container)
  * [Manual Installation of Development Tools](#manual-installation-of-development-tools)
      * [Java Platform JDK 11](#java-platform-jdk-11)
      * [Maven](#maven)
      * [Git Client](#git-client)
      * [Go](#go)
      * [Node JS](#node-js)
* [Build Steps](#build-steps)

## Development Tools

If you would like to build your own copy of Athenz rather than
using the pre-built binary packages, then here is the list of
development tools you need to have installed on your system.

### Build Within Docker Container

You can replicate the container environment that Athenz users within
Screwdriver to build and deploy Athenz packages. You can start a new
container using the `openjdk:11` image. Once you check out the Athenz
source tree, you can execute the `install_deps.sh` script
to install the required development tools:

```shell
$ git clone https://github.com/AthenZ/athenz.git
$ cd athenz
$ sh screwdriver/scripts/install_deps.sh
```

### Manual Installation of Development Tools

#### Java Platform JDK 11

To build Athenz components, you must have Java Platform JDK 11 installed
on your machine. The main authorization services - ZMS and ZTS, are
written in Java and using embedded Jetty.

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

Install go 1.21.5 or newer version by following the directions at
[Getting Started - The Go Programming Language](https://golang.org/doc/install).

Make sure you have set the [$GOPATH environment variable](https://pkg.go.dev/cmd/go#hdr-GOPATH_environment_variable)
and that you have `$GOPATH/bin` in your `$PATH`.

```shell
$ export GOPATH=<gopath-directory>
$ mkdir -p $GOPATH/bin
$ export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
````

#### Node JS

Install node 18.x by following the directions at
[Node.js JavaScript Runtime](https://nodejs.org/en/)

Verify that you have the required minimum version of `node`,
`npm` and `nodemon` binaries installed on your system and are included
in your runtime path:

```shell
$ node --version
v18.19.0
$ npm -v
10.3.0
$ npm install -g nodemon
$ nodemon --version
3.0.3
```

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
