'use strict';

var url = require('url');
var path = require('path');
var axios = require('axios');
var debug = require('debug')('rdl-rest');
var os = require('os');
var clone = require('lodash.clone');

// Normalize the method name from the rdl name
// getFoo putBar deleteBaz, etc
// ignore from istanbul coverage because rdl-rest is external library
/*istanbul ignore next*/
var _normalizeMethod = function(route, proto) {
    var name = route.type.charAt(0).toUpperCase() + route.type.substr(1);
    var method = route.method.toLowerCase();
    if (proto[method + name]) {
        var item = route.inputs.filter(function(o) {
            return (o.name === 'detail');
        })[0];
        // ignore from istanbul coverage because rdl-rest is external library
        /*istanbul ignore next*/
        if (item) {
            name = item.type.charAt(0).toUpperCase() + item.type.substr(1);
            debug('name collision', item.type, route);
        }
    }
    debug('method', method + name);
    return method + name;
};

// ignore from istanbul coverage because rdl-rest is external library
/*istanbul ignore next*/
var forwardHeaders = ['authorization', 'cookie', 'user-agent', 'client-ip', 'x-forwarded-for', 'bucket'];

// ignore from istanbul coverage because rdl-rest is external library
/*istanbul ignore next*/
var _isSuccessResponseCode = function(responseCode) {
  return responseCode && responseCode >= 200 && responseCode < 300;
};

// ignore from istanbul coverage because rdl-rest is external library
/*istanbul ignore next*/
var _isJsonResponse = function(response) {
  return typeof response === 'object';
};

// Set the headers on the request
// Defaults to content-type unless scoped to a request
// then it forwards the defined headers across
// then it adds the referer as the host calling it
// ignore from istanbul coverage because rdl-rest is external library
/*istanbul ignore next*/
var _setHeaders = function(headers) {
    headers = headers || {};
    if (this.request) {
        //Forward the headers from the request
        forwardHeaders.forEach(function(name) {
            if (this.request.headers[name]) {
                headers[name] = this.request.headers[name];
            }
        }.bind(this));
        headers.referer = url.format({
            protocol: this.request.protocol,
            host: os.hostname(),
            pathname: url.parse(this.request.originalUrl, true).pathname,
            path: this.request.originalUrl,
            query: this.request.query
        });
    }

    headers['content-type'] = 'application/json';

    if (this.headers) {
        if (typeof this.headers === 'function') {
            headers = this.headers(headers);
        } else {
            Object.keys(this.headers).forEach(function(name) {
                var value = this.headers[name];
                if (typeof value === 'function') {
                    value = value(this.request);
                }
                headers[name] = value;
            }.bind(this));
        }
    }
    return headers;
};

// ignore from istanbul coverage because rdl-rest is external library
/*istanbul ignore next*/
var _normalizeParts = function(route, data) {
    var parts = url.parse(this.apiHost, true);

    var options = clone(this.requestOpts);

    //Cloning to avoid data corruption from the caller
    debug('data start', data);
    data = JSON.parse(JSON.stringify(data));

    options.method = route.method;

    options.headers = this._setHeaders(data.headers);
    delete data.headers;

    parts.pathname = path.join(parts.pathname, route.path);
    if (this.request && this.request.requestId) {
        parts.query.requestId = this.request.requestId;
    }
    route.inputs.forEach(function(item) {
        var name = item.name;
        var value = data[name];
        if (value) {
            if (item.header) {
                options.headers[item.header.toLowerCase()] = value;
                delete data[name];
            }
            if (item.queryParam) {
                parts.query[item.queryParam] = value;
                delete data[name];
            }
            if (item.pathParam) {
                parts.pathname = parts.pathname.replace('{' + name + '}', value);
                delete data[name];
            }
        }
    });
    delete parts.href;
    delete parts.path;
    options.json = true;
    options.url = url.format(parts);
    data = this._normalizeData(route, data);
    if (data) {
        options.data = data;
    } else {
      delete options.data;
    }
    debug('parts', options);
    return options;
};

// ignore from istanbul coverage because rdl-rest is external library
/*istanbul ignore next*/
var _normalizeData = function(route, data) {
    var out = {}, extra;
    var bodyItem = route.inputs.filter(function(item) {
        if (!item.pathParam && !item.header && !item.queryParam) {
            return true;
        }
        return false;
    });

    if (bodyItem.length) {
        out = data[bodyItem[0].name];
        delete data[bodyItem[0].name];
    }

    extra = Object.keys(data).length;
    if (extra) {
        debug('Found ' + extra + ' items in payload:', data);
    }
    if (!Object.keys(out).length) {
        out = null;
    }
    debug('payload', out);
    return out;
};

// ignore from istanbul coverage because rdl-rest is external library
/*istanbul ignore next*/
var generate = function(rdl, apiHost, mHeaders, requestOpts) {
    var RDLRest = function (req, headers) {
        if (!(this instanceof RDLRest)) {
            return new RDLRest(req, headers);
        }
        this.apiHost = apiHost;
        this.request = req;
        this.headers = headers || mHeaders;
        this.requestOpts = requestOpts || {
            timeout: 4000
        };
    };

    RDLRest.prototype._normalizeParts = _normalizeParts;
    RDLRest.prototype._normalizeData = _normalizeData;
    RDLRest.prototype._setHeaders = _setHeaders;

    rdl.resources.forEach(function(route) {
        var method = _normalizeMethod(route, RDLRest.prototype);
        RDLRest.prototype[method] = function(data, callback) {
            if (typeof data === 'function') {
                callback = data;
                data = {};
            }
            if (!data || !callback) {
                throw(new Error('Invalid number of arguments passed while calling: ' + method));
            }
            var parts = this._normalizeParts(route, data);
            var start = Date.now();
            var req = this.request;
            var done = function(err, json, res) {
                var time = Date.now() - start + 'ms';
                if (req && req.log && req.error) {
                    if (err) {
                        req.error('rdl-rest', time, err);
                    } else {
                        req.log('rdl-rest', time, json);
                    }
                }
                callback(err, json, res);
            };
            let handleResponse = function (err, json, res) {
                var isJson = _isJsonResponse(json);
                var isSuccessResponse = _isSuccessResponseCode(res && res.statusCode);
                if (isSuccessResponse && !isJson) {
                  if (res && res.statusCode !== 200) {
                    json = {};
                    isJson = true;
                  }
                }
                if (err || !isSuccessResponse || !isJson) {
                    err = {
                        status: res && res.status,
                        message: json,
                        error: err
                    };
                    if (!isJson) {
                        json = null;
                    }
                }
                done(err, json, res);
            }
            return axios
            .request(parts)
            .then((res) => {
                let json = res.data;
                handleResponse(null, json, res);
            })
            .catch((err) => {
                let json = err.response && err.response.data;
                handleResponse(err, json, err.response);
            });
        };
    });

    return RDLRest;
};

// ignore from istanbul coverage because rdl-rest is external library
/*istanbul ignore next*/
module.exports = function(config) {
    config = config || {};
    if (!config.rdl) {
        throw(new Error('RDL spec not provided'));
    }
    if (!config.apiHost) {
        throw(new Error('apiHost is required'));
    }
    //Create the base client from the RDL
    var Client = generate(config.rdl, config.apiHost, config.headers, config.requestOpts);

    var factory = function(req, headers, cb) {
        var client =  new Client(req, headers);
        if (cb) {
            cb(client);
        }
        return client;
    };

    factory.Client = Client;

    //Return a factory to create a new client with scoped to a request
    return factory;
};
