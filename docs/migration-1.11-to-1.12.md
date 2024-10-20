Athenz Migration Guide from 1.11.x to 1.12.x
==============================================


Athenz 1.12.x includes the following changes:

- Upgrade to Jetty 12.x / EE10 Release using Jakarta 6.x
- Remove all deprecated methods from server side interfaces
- Migrate all aws v1 usage from server side code to aws v2 since v1 sdk is EOL
- Migrate Apache HttpClient 4.x to 5.x
- Server builds are released w/ JDK 17 due to jetty requirement but all client libraries are continued to be built and
  published with JDK 11 support
- replace jjwt library with nimbus-jwt library
- CI/CD pipeline will be moved from SD to GitHub Actions
- Move AWSPrivateKeyStore implementation from server-common to auth-core where it belongs with the correct package name
- Remove single email notification support and only support consolidated email notifications (there is no point of
  spamming the admin with 20 separate emails where a single email can include all the roles that the admin needs to
  review)

# Factory Class Renames

All factory implementations that involve aws have been moved into its own library: athenz-server-aws-common.
Additionally, some factory implementations were in the wrong module so they have been moved as well. Please review your
deployment configuration settings and make the necessary changes:

| Old class name                                                                  | New class name                                                               |
|---------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| com.yahoo.athenz.auth.impl.aws.AwsPrivateKeyStoreFactory                        | io.athenz.server.aws.common.key.impl.S3PrivateKeyStoreFactory                |
| com.yahoo.athenz.zms.store.impl.JDBCObjectStoreFactory                          | com.yahoo.athenz.common.server.store.impl.JDBCObjectStoreFactory             |
| com.yahoo.athenz.common.server.notification.impl.NotificationServiceFactoryImpl | io.athenz.server.aws.common.notification.impl.SESNotificationServiceFactory  |
| com.yahoo.athenz.zms.store.impl.dynamodb.DynamoDBAuthHistoryStoreFactory        | io.athenz.server.aws.common.store.impl.DynamoDBAuthHistoryStoreFactory       |
| com.yahoo.athenz.common.server.store.impl.S3ChangeLogStoreFactory               | io.athenz.server.aws.common.store.impl.S3ChangeLogStoreFactory               |
| com.yahoo.athenz.zts.cert.impl.DynamoDBCertRecordStoreFactory                   | io.athenz.server.aws.common.cert.impl.DynamoDBCertRecordStoreFactory         |
| com.yahoo.athenz.zts.cert.impl.DynamoDBSSHRecordStoreFactory                    | io.athenz.server.aws.common.cert.impl.DynamoDBSSHRecordStoreFactory          |
| com.yahoo.athenz.zts.workload.impl.DynamoDBWorkloadRecordStoreFactory           | io.athenz.server.aws.common.workload.impl.DynamoDBWorkloadRecordStoreFactory |
| com.yahoo.athenz.zts.store.impl.ZMSFileChangeLogStoreFactory                    | com.yahoo.athenz.common.server.store.impl.ZMSFileChangeLogStoreFactory       |
| com.yahoo.athenz.zts.cert.impl.JDBCCertRecordStoreFactory                       | com.yahoo.athenz.common.server.cert.impl.JDBCCertRecordStoreFactory          |
| com.yahoo.athenz.zts.cert.impl.JDBCSSHRecordStoreFactory                        | com.yahoo.athenz.common.server.cert.impl.JDBCSSHRecordStoreFactory           |

# Deprecated Methods Removed

The deprecated methods from the server side interfaces have been removed. If you're using the default implementations
provided as part of the Athenz release, then no changes are necessary since those are already updated accordingly.
Otherwise, for any internal implementations of these interfaces, you must make the necessary changes before deployment.

Interface: com.yahoo.athenz.auth.PrivateKeyStore<br>
Module: athenz-auth-core

| Deprecated API                                                                              | Replacement API                                                                                              |
|---------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| PrivateKey getPrivateKey(String service, String serverHostName, StringBuilder privateKeyId) | ServerPrivateKey getPrivateKey(String service, String serverHostName, String serverRegion, String algorithm) |
| String getApplicationSecret(String appName, String keyName)                                 | char\[] getSecret(String appName, String keygroupName, String keyName)                                       |
| char\[] getSecret(String appName, String keyName)                                           | char\[] getSecret(String appName, String keygroupName, String keyName)                                       |

Interface: com.yahoo.athenz.common.server.cert.CertSigner<br>
Module: athenz-server-common

| Deprecated API                                                                                                                     | Replacement API                                                                                                                                                                       |
|------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| String generateX509Certificate(String csr, String keyUsage, int expiryTime)                                                        | String generateX509Certificate(String provider, String certIssuer, String csr, String keyUsage, int expiryTime, Priority priority, String signerKeyId) throws ServerResourceException |
| String generateX509Certificate(String provider, String certIssuer, String csr, String keyUsage, int expiryTime)                    | String generateX509Certificate(String provider, String certIssuer, String csr, String keyUsage, int expiryTime, Priority priority, String signerKeyId) throws ServerResourceException |
| String generateX509Certificate(String provider, String certIssuer, String csr, String keyUsage, int expiryTime, Priority priority) | String generateX509Certificate(String provider, String certIssuer, String csr, String keyUsage, int expiryTime, Priority priority, String signerKeyId) throws ServerResourceException |
| String getCACertificate()                                                                                                          | String getCACertificate(String provider, String signerKeyId)                                                                                                                          |
| String getCACertificate(String provider)                                                                                           | String getCACertificate(String provider, String signerKeyId)                                                                                                                          |

Interface: com.yahoo.athenz.common.server.cert.SSHSigner<br>
Module: athenz-server-common

| Deprecated API                                                                                                                        | Replacement API                                                                                                                                                                    |
|---------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SSHCertificates generateCertificate(Principal principal, SSHCertRequest certRequest, SSHCertRecord certRecord, final String certType) | SSHCertificates generateCertificate(Principal principal, SSHCertRequest certRequest, SSHCertRecord certRecord, String certType, String signerKeyId) throws ServerResourceException |
| String getSignerCertificate(String certType)                                                                                          | String getSignerCertificate(String certType, String signerKeyId) throws ServerResourceException                                                                                    |

Interface: com.yahoo.athenz.common.server.notification.NotificationServiceFactory<br>
Module: athenz-server-common

| Deprecated API               | Replacement API                                                                            |
|------------------------------|--------------------------------------------------------------------------------------------|
| NotificationService create() | NotificationService create(PrivateKeyStore privateKeyStore) throws ServerResourceException |

Interface: com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcher<br>
Module: athenz-dynamodb-client-factory

| Deprecated API                                                                                                                    | Replacement API                                                                                                                                       |
|-----------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| DynamoDBClientAndCredentials getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender, PrivateKeyStore keyStore) | DynamoDBClientAndCredentials getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender, DynamoDBClientSettings dynamoDBClientSettings |

# ZTS Provider JWKS Uri

The jwt processing library now requires that all initializers include the jwks uri so, when the private keys are
rotated, the library can automatically fetch the latest set of public keys to validate the signature. As part of this
change, the ZTS provider must be configured with its own jwks uri. Please update your deployment setup and make sure you
have configured the following system property:

    athenz.zts.provider_jwks_uri=<zts-server-endpoint>/zts/v1/oauth2/keys?rfc=true

# AWS Deployment Changes

The server no longer automatically enables Dynamic configuration library support for the AWS Parameter store since not
everyone is running their Athenz ZMS/ZTS instances in AWS. To enable support the following changes must be made to your
deployment pipeline:

ZMS Deployment:

- Make sure athenz-server-aws-common module along with all of its dependencies is deployed as part of your application
- Update your startup script and make sure the following system properties are set as part of your ZMS
  deployment:
  `-Dathenz.config.providers=io.athenz.server.aws.common.config.impl.ConfigProviderParametersStore -Dathenz.config.source_paths=aws-param-store://zms`

ZTS Deployment:

- Make sure athenz-server-aws-common module along with all of its dependencies is deployed as part of your application
- Update your startup script and make sure the following system properties are set as part of your ZMS
  deployment:
  `-Dathenz.config.providers=io.athenz.server.aws.common.config.impl.ConfigProviderParametersStore -Dathenz.config.source_paths=aws-param-store://zts`
