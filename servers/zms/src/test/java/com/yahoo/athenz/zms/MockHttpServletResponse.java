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

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@SuppressWarnings("RedundantThrows")
class MockHttpServletResponse implements HttpServletResponse {

    private final Map<String, String> headers = new HashMap<>();

    public MockHttpServletResponse() {
    }
    
    @Override
    public String getCharacterEncoding() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String getContentType() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        // Auto-generated method stub
        return null;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        // Auto-generated method stub
        return null;
    }

    @Override
    public void setCharacterEncoding(String charset) {
        // Auto-generated method stub
    }

    @Override
    public void setContentLength(int len) {
        // Auto-generated method stub
    }

    @Override
    public void setContentLengthLong(long len) {
        // Auto-generated method stub
    }

    @Override
    public void setContentType(String type) {
        // Auto-generated method stub
    }

    @Override
    public void setBufferSize(int size) {
        // Auto-generated method stub
    }

    @Override
    public int getBufferSize() {
        // Auto-generated method stub
        return 0;
    }

    @Override
    public void flushBuffer() throws IOException {
        // Auto-generated method stub
    }

    @Override
    public void resetBuffer() {
        // Auto-generated method stub
    }

    @Override
    public boolean isCommitted() {
        // Auto-generated method stub
        return false;
    }

    @Override
    public void reset() {
        // Auto-generated method stub
    }

    @Override
    public void setLocale(Locale loc) {
        // Auto-generated method stub
    }

    @Override
    public Locale getLocale() {
        // Auto-generated method stub
        return null;
    }

    @Override
    public void addCookie(Cookie cookie) {
        // Auto-generated method stub
    }

    @Override
    public boolean containsHeader(String name) {
        // Auto-generated method stub
        return false;
    }

    @Override
    public String encodeURL(String url) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String encodeRedirectURL(String url) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String encodeUrl(String url) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public String encodeRedirectUrl(String url) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        // Auto-generated method stub
    }

    @Override
    public void sendError(int sc) throws IOException {
        // Auto-generated method stub
    }

    @Override
    public void sendRedirect(String location) throws IOException {
        // Auto-generated method stub
    }

    @Override
    public void setDateHeader(String name, long date) {
        // Auto-generated method stub
    }

    @Override
    public void addDateHeader(String name, long date) {
        // Auto-generated method stub
    }

    @Override
    public void setHeader(String name, String value) {
        // Auto-generated method stub
    }

    @Override
    public void addHeader(String name, String value) {
        headers.put(name, value);
    }

    @Override
    public void setIntHeader(String name, int value) {
        // Auto-generated method stub
    }

    @Override
    public void addIntHeader(String name, int value) {
        // Auto-generated method stub
    }

    @Override
    public void setStatus(int sc) {
        // Auto-generated method stub
    }

    @Override
    public void setStatus(int sc, String sm) {
        // Auto-generated method stub
    }

    @Override
    public int getStatus() {
        // Auto-generated method stub
        return 0;
    }

    @Override
    public String getHeader(String name) {
        return headers.get(name);
    }

    @Override
    public Collection<String> getHeaders(String name) {
        // Auto-generated method stub
        return null;
    }

    @Override
    public Collection<String> getHeaderNames() {
        // Auto-generated method stub
        return null;
    }
}
