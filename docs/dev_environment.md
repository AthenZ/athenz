# Development Environment
-------------------------

* [Development Tools](#development-tools)
    * [Java Platform JDK 8](#java-platform-jdk-8)
    * [Maven](#maven)
    * [Git Client](#git-client)
    * [Go](#go)
* [Build Steps](#build-steps)

## Development Tools
--------------------

If you would like to build your own copy of Athenz rather than
using the pre-built binary packages, then here is the list of
development tools you need to have installed on your system.

### Java Platform JDK 8
-----------------------

To build Athenz components, you must have Java Platform JDK 8 installed
on your machine. The main authorization services - ZMS and ZTS, are
written in Java and using embedded Jetty.

[Oracle Java Platform JDK 8](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)

Athenz has been developed and tested with Oracle Java Platform JDK 8.
However, it should compile and run without any issues with OpenJDK 8 as well.

### Maven
---------

Download and install [Apache Maven](http://maven.apache.org/download.cgi).

### Git Client
--------------

If you don't have git client installed on your host, you can download
one from [Git website](https://git-scm.com/downloads)

### Go
------

Install go by following the directions at
[Getting Started - The Go Programming Language](https://golang.org/doc/install).

## Build Steps
--------------

To build Athenz components, change to the top level directory where
Athenz code has been checked out and execute:

```
git clone https://github.com/yahoo/AtheNZ.git
cd AtheNZ
mvn clean install
```

