/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

var url = require('url');
var path = require('path');
var axios = require('axios');
var debug = require('debug')('rdl-rest');
var os = require('os');
var clone = require('lodash.clone');

// Normalize the method name from the rdl name
// getFoo putBar deleteBaz, etc
var _normalizeMethod = function (route, proto) {
    var name = route.type.charAt(0).toUpperCase() + route.type.substr(1);
    var method = route.method.toLowerCase();
    // check if the method name is specified to be overridden
    if (route.name) {
        name = route.name.charAt(0).toLowerCase() + route.name.substr(1);
        method = '';
    }
    if (proto[method + name] && route.inputs) {
        var item = route.inputs.filter(function (o) {
            return o.name === 'detail';
        })[0];
        /*istanbul ignore next*/
        if (item) {
            name = item.type.charAt(0).toUpperCase() + item.type.substr(1);
            debug('name collision', item.type, route);
        }
    }
    debug('method', method + name);
    return method + name;
};

var forwardHeaders = [
    'authorization',
    'cookie',
    'user-agent',
    'client-ip',
    'x-forwarded-for',
    'bucket',
];

var _isSuccessResponseCode = function (responseCode) {
    return responseCode && responseCode >= 200 && responseCode < 300;
};

var _isJsonResponse = function (response) {
    return typeof response === 'object';
};

// Set the headers on the request
// Defaults to content-type unless scoped to a request
// then it forwards the defined headers across
// then it adds the referer as the host calling it
var _setHeaders = function (headers) {
    headers = headers || {};
    if (this.request) {
        //Forward the headers from the request
        forwardHeaders.forEach(
            function (name) {
                if (this.request.headers[name]) {
                    headers[name] = this.request.headers[name];
                }
            }.bind(this)
        );
        headers.referer = url.format({
            protocol: this.request.protocol,
            host: os.hostname(),
            pathname: url.parse(this.request.originalUrl, true).pathname,
            path: this.request.originalUrl,
            query: this.request.query,
        });
    }

    headers['content-type'] = 'application/json';

    if (this.headers) {
        if (typeof this.headers === 'function') {
            headers = this.headers(headers, this.request);
        } else {
            Object.keys(this.headers).forEach(
                function (name) {
                    var value = this.headers[name];
                    if (typeof value === 'function') {
                        value = value(this.request);
                    }
                    headers[name] = value;
                }.bind(this)
            );
        }
    }
    return headers;
};

var _normalizeParts = function (route, data) {
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
    route.inputs &&
        route.inputs.forEach(function (item) {
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
                    parts.pathname = parts.pathname.replace(
                        '{' + name + '}',
                        value
                    );
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

var _normalizeData = function (route, data) {
    var out = {},
        extra;
    var bodyItem = route.inputs
        ? route.inputs.filter(function (item) {
              if (!item.pathParam && !item.header && !item.queryParam) {
                  return true;
              }
              return false;
          })
        : [];

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

var _methodCb = function (data, callback, route) {
    var parts = this._normalizeParts(route, data);
    var start = Date.now();
    var req = this.request;
    var done = function (err, json, res) {
        var time = Date.now() - start + 'ms';
        if (err && req && req.error) {
            req.error('rdl-rest', time, err);
        } else {
            debug(time, json);
        }
        callback(err, json, res);
    };

    let handleResponse = function (err, json, res) {
        var isJson = _isJsonResponse(json);
        var isSuccessResponse = _isSuccessResponseCode(res && res.status);
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
                error: err,
            };
            if (!isJson) {
                json = null;
            }
        }
        done(err, json, res);
    };

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

var generate = function (rdl, apiHost, mHeaders, requestOpts) {
    var RDLRest = function (req, headers) {
        if (!(this instanceof RDLRest)) {
            return new RDLRest(req, headers);
        }
        this.apiHost = apiHost;
        this.request = req;
        this.headers = headers || mHeaders;
        this.requestOpts = requestOpts || {
            timeout: 4000,
        };
    };

    var methodRouteMapping = {};

    RDLRest.prototype._normalizeParts = _normalizeParts;
    RDLRest.prototype._normalizeData = _normalizeData;
    RDLRest.prototype._setHeaders = _setHeaders;

    rdl.resources.forEach(function (route) {
        var method = _normalizeMethod(route, RDLRest.prototype);

        if (methodRouteMapping[method]) {
            methodRouteMapping[method].push(route);
        } else {
            methodRouteMapping[method] = [route];
        }

        RDLRest.prototype[method] = function (data, callback) {
            if (typeof data === 'function') {
                callback = data;
                data = {};
            }
            if (!data || !callback) {
                throw new Error(
                    'Invalid number of arguments passed while calling: ' +
                        method
                );
            }
            var matchedRoutes = methodRouteMapping[method];
            if (matchedRoutes.length > 1) {
                var inputParams = Object.keys(data);
                matchedRoutes = matchedRoutes.filter(function (methodRoute) {
                    var routeParams = methodRoute.inputs.map(function (input) {
                        return input.name;
                    });
                    var matchedParams = inputParams.filter(function (name) {
                        return routeParams.indexOf(name) > -1;
                    });
                    return matchedParams.length === inputParams.length;
                });
            }

            if (!matchedRoutes.length) {
                throw new Error('Invalid API arguments');
            }

            if (matchedRoutes.length > 1) {
                debug(data, ' matched multiple routes for method ', method);
            }

            _methodCb.call(this, data, callback, matchedRoutes[0]);
        };
    });

    return RDLRest;
};

module.exports = function (config) {
    config = config || {};
    if (!config.rdl) {
        throw new Error('RDL spec not provided');
    }
    if (!config.apiHost) {
        throw new Error('apiHost is required');
    }
    //Create the base client from the RDL
    var Client = generate(
        config.rdl,
        config.apiHost,
        config.headers,
        config.requestOpts
    );

    var factory = function (req, headers, cb) {
        var client = new Client(req, headers);
        if (cb) {
            cb(client);
        }
        return client;
    };

    factory.Client = Client;

    //Return a factory to create a new client with scoped to a request
    return factory;
};
