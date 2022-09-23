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
package com.yahoo.athenz.zms;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpUpgradeHandler;
import jakarta.servlet.http.Part;

@SuppressWarnings("RedundantThrows")
class MockHttpServletRequest implements HttpServletRequest {

    private final Map<String, String> headers = new HashMap<>();
    private final Map<String, Object> attributes = new HashMap<>();
    
    public MockHttpServletRequest() {
    }
    
    public void addHeader(String name, String value) {
        headers.put(name, value);
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getCharacterEncoding() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public void setCharacterEncoding(String env) throws UnsupportedEncodingException {
        // Auto-generated method stub
    }

    @Override
    public int getContentLength() {
        // Auto-generated method stub
        return 0;
    }

    @Override
    public long getContentLengthLong() {
        // Auto-generated method stub
        return 0;
    }

    @Override
    public String getContentType() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getParameter(String name) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public Enumeration<String> getParameterNames() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String[] getParameterValues(String name) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getProtocol() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getScheme() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getServerName() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public int getServerPort() {
        // Auto-generated method stub
        return 0;
    }

    @Override
    public BufferedReader getReader() throws IOException {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getRemoteAddr() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getRemoteHost() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public void setAttribute(String name, Object o) {
        attributes.put(name, o);
    }

    @Override
    public void removeAttribute(String name) {
        // Auto-generated method stub
    }

    @Override
    public Locale getLocale() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public Enumeration<Locale> getLocales() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public boolean isSecure() {
        return true;
    }

    @Override
    public RequestDispatcher getRequestDispatcher(String path) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getRealPath(String path) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public int getRemotePort() {
        // Auto-generated method stub
        return 0;
    }

    @Override
    public String getLocalName() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getLocalAddr() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public int getLocalPort() {
        // Auto-generated method stub
        return 0;
    }

    @Override
    public ServletContext getServletContext() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public AsyncContext startAsync() throws IllegalStateException {
        // Auto-generated method stub
        return null;
    }

    @Override
    public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse)
            throws IllegalStateException {
        // Auto-generated method stub
        return null;
    }

    @Override
    public boolean isAsyncStarted() {
        // Auto-generated method stub
        return false;
    }

    @Override
    public boolean isAsyncSupported() {
        // Auto-generated method stub
        return false;
    }

    @Override
    public AsyncContext getAsyncContext() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public DispatcherType getDispatcherType() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getAuthType() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public Cookie[] getCookies() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public long getDateHeader(String name) {
        // Auto-generated method stub
        return 0;
    }

    @Override
    public String getHeader(String name) {
        return headers.get(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public int getIntHeader(String name) {
        // Auto-generated method stub
        return 0;
    }

    @Override
    public String getMethod() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getPathInfo() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getPathTranslated() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getContextPath() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getQueryString() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getRemoteUser() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public boolean isUserInRole(String role) {
        // Auto-generated method stub
        return false;
    }

    @Override
    public Principal getUserPrincipal() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getRequestedSessionId() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getRequestURI() {
        return "/zms/v1/request";
    }

    @Override
    public StringBuffer getRequestURL() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getServletPath() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public HttpSession getSession(boolean create) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public HttpSession getSession() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String changeSessionId() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public boolean isRequestedSessionIdValid() {
        // Auto-generated method stub
        return false;
    }

    @Override
    public boolean isRequestedSessionIdFromCookie() {
        // Auto-generated method stub
        return false;
    }

    @Override
    public boolean isRequestedSessionIdFromURL() {
        // Auto-generated method stub
        return false;
    }

    @Override
    public boolean isRequestedSessionIdFromUrl() {
        // Auto-generated method stub
        return false;
    }

    @Override
    public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
        // Auto-generated method stub
        return false;
    }

    @Override
    public void login(String username, String password) throws ServletException {
        // Auto-generated method stub
    }

    @Override
    public void logout() throws ServletException {
        // Auto-generated method stub
    }

    @Override
    public Collection<Part> getParts() throws IOException, ServletException {
        // Auto-generated method stub
        return null;
    }

    @Override
    public Part getPart(String name) throws IOException, ServletException {
        // Auto-generated method stub
        return null;
    }

    @Override
    public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass) throws IOException, ServletException {
        // Auto-generated method stub
        return null;
    }
}
