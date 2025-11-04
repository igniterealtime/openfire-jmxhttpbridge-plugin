package org.igniterealtime.openfire.plugins.jmxhttpbridge.web;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.XMPPServerInfo;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

/**
 * A servlet that responds with very basic version information (as a JSON structure) for the Openfire instance.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class VersionServlet extends HttpServlet
{
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        final XMPPServerInfo serverInfo = XMPPServer.getInstance().getServerInfo();
        final JSONObject config = new JSONObject();
        config.put("version", serverInfo.getVersion());
        config.put("hostname", serverInfo.getHostname());
        config.put("xmppdomain", serverInfo.getXMPPDomain());
        config.put("lastStarted", serverInfo.getLastStarted().getTime());

        final String responseBody = config.toString();
        response.setHeader("Content-Type", "application/json");
        response.setHeader("Content-Length", String.valueOf(responseBody.length()));
        try ( final Writer writer = response.getWriter() ) {
            writer.write(responseBody);
            writer.flush();
        }
    }
}
