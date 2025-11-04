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
package org.igniterealtime.openfire.plugins.jmxhttpbridge.web;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.cluster.ClusterManager;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

/**
 * A servlet that responds with very basic health information (as a JSON structure) for the Openfire instance.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class HealthServlet extends HttpServlet
{
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        final JSONObject config = new JSONObject();
        config.put("isStarted", XMPPServer.getInstance().isStarted());
        config.put("isClusteringEnabled", ClusterManager.isClusteringEnabled());
        config.put("isClusteringStarted", ClusterManager.isClusteringStarted());
        config.put("hasPluginManagerExecuted", XMPPServer.getInstance().getPluginManager().isExecuted());

        final String responseBody = config.toString();
        response.setHeader("Content-Type", "application/json");
        response.setHeader("Content-Length", String.valueOf(responseBody.length()));
        try ( final Writer writer = response.getWriter() ) {
            writer.write(responseBody);
            writer.flush();
        }
    }
}
