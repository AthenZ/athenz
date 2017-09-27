zts-nodejs-client
===============

A Node.js client library to access ZTS. This client library is generated
from the RDL(zts.json).

https://www.npmjs.com/package/@athenz/zts-client

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
    ztshost: process.env.ZTS_SERVER || 'localhost',
    zts: 'https://localhost:4443/zts/v1/',
    strictSSL: false,
    logLevel: 'debug',
    tokenMinExpiryTime: 900,
    tokenRefresh: 1800,
    disableCache: false
  };
};
```

## License

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
