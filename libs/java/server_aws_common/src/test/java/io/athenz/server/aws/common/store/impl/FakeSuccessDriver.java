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
package io.athenz.server.aws.common.store.impl;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverPropertyInfo;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * Minimal fake JDBC driver so tests can exercise verifyConnection()'s success path
 * without a live database. Only connect()/acceptsURL() matter; the returned Connection
 * is a no-op proxy since verifyConnection() only checks it for non-null before closing it.
 */
class FakeSuccessDriver implements Driver {

    static final String URL = "jdbc:athenztest://fake/db";

    @Override
    public boolean acceptsURL(String url) {
        return URL.equals(url);
    }

    @Override
    public Connection connect(String url, Properties info) {
        return (Connection) Proxy.newProxyInstance(
                Connection.class.getClassLoader(),
                new Class<?>[] { Connection.class },
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "isClosed":
                            return false;
                        case "equals":
                            return proxy == (args != null && args.length > 0 ? args[0] : null);
                        case "hashCode":
                            return System.identityHashCode(proxy);
                        case "toString":
                            return "FakeConnection";
                        default:
                            return null;
                    }
                });
    }

    @Override
    public int getMajorVersion() {
        return 1;
    }

    @Override
    public int getMinorVersion() {
        return 0;
    }

    @Override
    public boolean jdbcCompliant() {
        return false;
    }

    @Override
    public Logger getParentLogger() {
        throw new UnsupportedOperationException();
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
        return new DriverPropertyInfo[0];
    }
}
