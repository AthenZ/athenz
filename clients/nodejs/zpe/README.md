zpe-nodejs-client
===============

Athenz ZPE client lib to perform data plane authorization for client requests

https://www.npmjs.com/package/@athenz/zpe-client

## Contents

* [Summary](#summary)
* [Details](#details)


## Summary

This is the ZPE(AuthZ Policy Engine) front-end API to perform client
access authorization to resources.

The implementation is thread safe.

## Details

--- Customizing configuration settings ---

The application can change these values by adding a following configuration file, 
and the file should be a module which exports a function returns the configuration object

File path:
```javascript
process.cwd() + '/config/config.js'
```

Configuration object:
```javascript
module.exports = function() {
  return {
    logLevel: 'debug',
    policyDir: '/home/athenz/var/zpe',
    tokenRefresh: 1800,
    policyRefresh: 1800,
    allowedOffset: '300',
    disableCache: false
  };
};
```

## License

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
