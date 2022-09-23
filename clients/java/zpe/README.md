# zpe_java_client

Athenz ZPE client lib to perform data plane authorization for client requests

## Contents

* [Summary](#summary)
* [Details](#details)


## Summary

This is the ZPE(AuthZ Policy Engine) front-end API to perform client
access authorization to resources.

The implementation is thread safe.

## Details

This library will be used by service components to check client access
authorization to resources supplied by the service component.

The library will read the authorization policies from the file system.
These policy files will be in JSON format as returned by the ZMS REST API:
getSignedPolicies().
The directory containing these policy files is by default /home/athenz/var/zpe
but will be configurable.

These authorization policies can be for several domains.

ZPE will monitor the directory for updates to the files or new files added.
As new files are deposited to the policy file directory, ZPE will read
in the new policies to replace the old ones or add them for a new domain.
Each policy file will be validated against its signature to ensure
validity of the policy data.

It is expected that each file contains all the policies for a domain.

The policy files can be deposited there in several ways:
1. Athenz Policy Updater
2. Manually deposited


System properties:

  athenz.zpe.policy_dir 
      Default value: ROOT + /var/zpe
      Should contain a valid directory path.

  athenz.zpe.monitor_timeout_secs 
      Default value: 300
      This time interval is used to check for changes to the policy files.

  athenz.zpe.cleanup_tokens_secs 
      Default value: 600 (10 minutes)
      This time interval is used to check for expired tokens in the cache.
      It is dependent on the athenz.zpe.monitor_timeout_secs.
      For intervals less than monitor_timeout_secs, the enforcement check
      will take place every monitor_timeout_secs seconds.
      For intervals greater than monitor_timeout_secs, enforcement checks (ec)
      will take place every: 
      ec * monitor_timeout_secs >= cleanup_tokens_secs 
      where ec is the smallest integer such that ec * monitor_timeout_secs >= cleanup_tokens_secs
      Ex: monitor_timeout_secs=300, cleanup_tokens_secs=500, ec = 600 seconds

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

