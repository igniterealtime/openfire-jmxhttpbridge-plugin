/*
 * Copyright (C) 2025 Ignite Realtime Foundation. All rights reserved.
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
package org.igniterealtime.openfire.plugins.jmxhttpbridge.web.admin;

import org.igniterealtime.openfire.plugins.jmxhttpbridge.StatsWebServer;
import org.igniterealtime.openfire.plugins.jmxhttpbridge.web.AuthFilter;
import org.jivesoftware.openfire.JMXManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.cluster.ClusterManager;
import org.jivesoftware.util.CookieUtils;
import org.jivesoftware.util.ParamUtils;
import org.jivesoftware.util.StringUtils;
import org.jivesoftware.util.WebManager;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

/**
 * A servlet that responds with very basic health information (as a JSON structure) for the Openfire instance.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class ConfigServlet extends HttpServlet
{
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        setDefaultAttributes(request, response);

        request.getRequestDispatcher("config-page.jsp").forward(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        final Map<String, Object> errors = new HashMap<>();
        request.setAttribute("errors", errors);

        // Place both current configuration, overridden with user-provided data, back on the request (so that
        // the end-user may correct data that does not validate properly).
        setDefaultAttributes(request, response);
        setUserProvidedAttributes(request, response);

        // Validate input data.
        final String portString = ParamUtils.getParameter(request,"port");
        Integer port = null;
        if (portString != null) {
            try {
                port = Integer.parseInt(portString);
                if (port < 1 || port > 65535) {
                    errors.put("port", "is not a valid port number");
                }
            } catch (NumberFormatException e) {
                errors.put("port", "is not a valid port number");
            }
        }

        final String secureportString = ParamUtils.getParameter(request,"secureport");
        Integer secureport = null;
        if (secureportString != null) {
            try {
                secureport = Integer.parseInt(secureportString);
                if (secureport < 1 || secureport > 65535) {
                    errors.put("secureport", "is not a valid port number");
                }
            } catch (NumberFormatException e) {
                errors.put("secureport", "is not a valid port number");
            }
        }

        final String authtypeValue = ParamUtils.getParameter(request,"authtype");
        AuthFilter.AuthType authType = null;
        if (authtypeValue == null) {
            errors.put("authtype", "is required");
        } else {
            try {
                authType = AuthFilter.AuthType.valueOf(authtypeValue);
            } catch (IllegalArgumentException e) {
                errors.put("authtype", "is not a valid authtype value");
            }
        }

        final String secretvalue = ParamUtils.getParameter(request,"secretvalue");
        if (authType == AuthFilter.AuthType.secret && (secretvalue == null || secretvalue.isEmpty())) {
            errors.put("secretvalue", "is required when authtype is 'secret'");
        }

        // When there are (validation) errors, do not process the input values.
        if (!errors.isEmpty()) {
            request.getRequestDispatcher("config-page.jsp").forward(request, response);
            return;
        }

        // Everything seems to check out. Process input values.
        StatsWebServer.JMXHTTPBRIDGE_WEBSERVER_PORT.setValue(port == null ? -1 : port);
        StatsWebServer.JMXHTTPBRIDGE_WEBSERVER_PORT_SECURE.setValue(secureport == null ? -1 : secureport);
        AuthFilter.JMXHTTPBRIDGE_WEBSERVER_AUTH_TYPE.setValue(authType);
        AuthFilter.JMXHTTPBRIDGE_WEBSERVER_AUTH_SECRET.setValue(secretvalue);

        // Update the audit log.
        final WebManager webManager = new WebManager();
        webManager.init(request, response, request.getSession(), request.getServletContext());
        webManager.logEvent("Updated JMX / HTTP bridge configuration.", String.format("Port: %d, Secure port: %d, AuthType: %s", port, secureport, authType));

        // Redirect to show the 'success' page.
        response.sendRedirect("config.jsp?success=true");
    }

    /**
     * Sets attributes that reflect the current configuration.
     */
    protected void setDefaultAttributes(HttpServletRequest request, HttpServletResponse response)
    {
        request.setAttribute("isJmxEnabled", JMXManager.isEnabled());
        request.setAttribute("port", StatsWebServer.JMXHTTPBRIDGE_WEBSERVER_PORT.getValue() == -1 ? null : StatsWebServer.JMXHTTPBRIDGE_WEBSERVER_PORT.getValue());
        request.setAttribute("secureport", StatsWebServer.JMXHTTPBRIDGE_WEBSERVER_PORT_SECURE.getValue() == -1 ? null : StatsWebServer.JMXHTTPBRIDGE_WEBSERVER_PORT_SECURE.getValue());
        request.setAttribute("authtype", AuthFilter.JMXHTTPBRIDGE_WEBSERVER_AUTH_TYPE.getValue());
        request.setAttribute("secretvalue", AuthFilter.JMXHTTPBRIDGE_WEBSERVER_AUTH_SECRET.getValue());
    }

    /**
     * Sets attributes that reflect configuration that was provided by POSTed parameters (in case it has validation
     * errors the end-user should see the data that it entered, and be allowed to correct it).
     */
    protected void setUserProvidedAttributes(HttpServletRequest request, HttpServletResponse response)
    {
        request.setAttribute("port", ParamUtils.getParameter(request,"port"));
        request.setAttribute("secureport", ParamUtils.getParameter(request,"secureport"));
        request.setAttribute("authtype", ParamUtils.getParameter(request,"authtype"));
        request.setAttribute("secretvalue", ParamUtils.getParameter(request,"secretvalue"));
    }
}
