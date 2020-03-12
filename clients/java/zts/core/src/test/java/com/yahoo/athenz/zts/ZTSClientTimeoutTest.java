/*
 * Copyright 2020 Verizon Media
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
package com.yahoo.athenz.zts;

import org.glassfish.jersey.client.JerseyClientBuilder;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;

import static org.testng.Assert.*;

public class ZTSClientTimeoutTest {

    private static final int sleep = 2000; // jetty call sleeps for 2 seconds
    private static final int timeout = 1000; // http client should timeout after 1 second
    private static final int port = 8088;
    private JettyServer server;

    @BeforeMethod
    public void setUp() {
        ZTSClient.setConnectionTimeouts(timeout, timeout);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    public void testZTSClientReadTimeoutForJerseyContainer() throws Exception {

        ZTSClientMock.setClientBuilder(new JerseyClientBuilder());
        server = new JettyServer(port);
        server.start();

        String baseUri = "http://localhost:" + port;

        ZTSClientMock ztsClient = new ZTSClientMock(baseUri);

        try {
            ztsClient.getRoleAccess("testDomain", "testPrincipal");
            fail("read timeout not set");
        } catch (ZTSClientException expected) {
            assertEquals(expected.code, ZTSClientException.BAD_REQUEST);
            assertEquals(
                    expected.getMessage(),
                    "ResourceException (400): java.net.SocketTimeoutException: Read timed out");
        }
        ztsClient.close();
        ZTSClientMock.setClientBuilder(null);
    }

    @Test
    public void testZTSClientReadTimeoutForRestEasyContainer() throws Exception {

        ZTSClientMock.setClientBuilder(new ResteasyClientBuilderImpl());
        server = new JettyServer(port);
        server.start();

        String baseUri = "http://localhost:" + port;

        ZTSClientMock ztsClient = new ZTSClientMock(baseUri);

        try {
            ztsClient.getRoleAccess("testDomain", "testPrincipal");
            fail("read timeout not set");
        } catch (ZTSClientException expected) {
            assertEquals(expected.code, ZTSClientException.BAD_REQUEST);
            assertEquals(
                    expected.getMessage(),
                    "ResourceException (400): RESTEASY004655: Unable to invoke request: java.net.SocketTimeoutException: Read timed out");
        }
        ztsClient.close();
        ZTSClientMock.setClientBuilder(null);
    }

    private static class JettyServer {

        private final int port;
        private Server server;

        public JettyServer(final int port) {
            this.port = port;
        }

        public void start() throws Exception {

            // Create a simple embedded jetty server on a given port

            server = new Server(port);

            // Define a raw servlet that does nothing but sleep for a configured
            // number of seconds so we get a read timeout from the client

            ServletHandler handler = new ServletHandler();
            server.setHandler(handler);
            handler.addServletWithMapping(SimpleServlet.class, "/*");

            // start our jetty server

            server.start();
        }

        public void stop() throws Exception {
            if (server != null) {
                server.stop();
                server = null;
            }
        }
    }

    public static class SimpleServlet extends HttpServlet {

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            try {
                Thread.sleep(sleep);
            } catch (InterruptedException ignored) {
            }
            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("<h1>We should always time-out and not get this</h1>");
        }
    }
}
