#!/usr/local/bin/bash

date

java -Dlogback.configurationFile="/opt/auth_history_syncer/conf/logback.xml" -jar /opt/auth_history_syncer/jars/auth_history_syncer-jar-with-dependencies.jar /opt/auth_history_syncer/conf/config.properties

date
