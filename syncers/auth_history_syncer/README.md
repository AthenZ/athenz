# auth_history_syncer

Extract authentication history from access logs and push to a data store.

##Running the syncer:

```shell
java -Dathenz.athenz_conf=/home/athenz/conf/athenz.conf  -Dathenz.root_dir=/home/athenz -Dathenz.access_log_dir=/home/athenz/logs/zts_server/ -cp $CLASSPATH:athenz-auth-history-syncer-X.XX.X.jar com.yahoo.athenz.syncer.auth.history.AuthHistorySyncer config.properties
```

##config.properties file
System properties should be specified in the config.properties file. The file template can be found in `resources/config.properties`

##Fetcher and Sender implementation
The syncer runs in two parts:
1. Fetching authentication history logs
2. Sending to data store.

Users may implement their own fetching / sending logic by implementing the following interfaces:


###AuthHistoryFetcher
Responsible for fetching access logs

Included implementations - `AwsAuthHistoryFetcher`, `LocalAuthHistoryFetcher`

###AuthHistoryFetcherFactory
Responsible for creating instances of AuthHistoryFetcher. To override, specify the class full path in the system property `auth_history_syncer.fetch_factory_class` 

Included implementations - `AwsAuthHistoryFetcherFactory`, `LocalAuthHistoryFetcherFactory`

###AuthHistorySender
Responsible for sending authentication history records to data store

Included implementation - `DynamoDBAuthHistorySender`

###AuthHistorySenderFactory
Responsible for creating instances of AuthHistorySender

Included implementation - `DynamoDBAuthHistorySenderFactory`