/**
 * Copyright 2017 Yahoo Inc.
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
package com.yahoo.athenz.example.centralized_authz;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.yahoo.athenz.zms.ZMSAuthorizer;

/*
  Very basic servlet.
*/
public class RecServlet extends HttpServlet {
    
    private static final long serialVersionUID = 2846506476975366921L;

    static final String URI_PREFIX = "/athenz-control/rec/v1";
    static final String ATHENZ_HEADER = "Athenz-Principal-Auth";
    String zmsUrl = null;
    
    public void init() throws ServletException {
        zmsUrl = System.getenv("ZMS_SERVER_URL");
    }

    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {

        // retrieve and verify that our request contains an Athenz
        // service authentication token
        
        String athenzServiceToken = request.getHeader(ATHENZ_HEADER);
        if (athenzServiceToken == null) {
            response.sendError(403, "Forbidden - No Athenz ServiceToken provided in request");
            return;
        }

        // our request starts with /athenz-control/rec/v1 so we're
        // going to skip that prefix
        
        String reqUri = request.getRequestURI().substring(URI_PREFIX.length());
        String responseText;
        String athenzResource;
        String athenzAction;
        switch (reqUri) {
            case "/movie":
                responseText = "Name: Slap Shot; Director: George Roy Hill";
                athenzResource = "rec.movie";
                athenzAction = "read";
                break;
            case "/tvshow":
                responseText = "Name: Middle; Channel: ABC";
                athenzResource = "rec.tvshow";
                athenzAction = "read";
                break;
            default:
                response.sendError(404, "Unknown endpoint");
                return;
        }
        
        // carry out the authorization check with the expected resource
        // and action values
        
        try (ZMSAuthorizer authorizer = new ZMSAuthorizer(zmsUrl, "recommend")) {
            boolean authorized = authorizer.access(athenzAction, athenzResource,
                    athenzServiceToken, null);
            if (!authorized) {
                response.sendError(403, "Forbidden - Athenz Authorization Rejected");
                return;
            }
        }
        response.setContentType("text/plain");
        PrintWriter out = response.getWriter();
        out.println(responseText);
    }

    protected void doPut(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
    }

    protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
    }

    protected void doDelete(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
    }
}

