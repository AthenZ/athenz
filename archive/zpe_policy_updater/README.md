ZPE Policy Updater Application

Like ZTS and ZPE, ZPU is only needed to support the decentralized authorization. The policy updater is the utility that retrieves from ZTS the policy files for provisioned domains on a host, which ZPE uses to evaluate access requests.This application must be setup as a cron job to periodically (e.g. every 2 hours) to update the policy files.

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
