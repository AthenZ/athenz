auth-core
=========

Core interfaces for authorization

https://www.npmjs.com/package/@athenz/auth-core

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
    principalIpCheckMode: 'OPS_WRITE',
    principalTokenAllowedOffset: '300',
    principalUserDomain: 'user',
    principalHeader: 'Athenz-Principal-Auth',
    tokenMaxExpiry: String(30 * 24 * 60 * 60),
    tokenNoExpiry: true,
    loglebel: 'debug'
  };
};
```

## License

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
