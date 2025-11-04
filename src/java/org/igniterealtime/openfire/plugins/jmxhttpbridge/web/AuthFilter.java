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

import javax.annotation.Nonnull;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.igniterealtime.openfire.plugins.jmxhttpbridge.JmxHttpBridgePlugin;
import org.jivesoftware.openfire.admin.AdminManager;
import org.jivesoftware.openfire.auth.AuthFactory;
import org.jivesoftware.openfire.auth.ConnectionException;
import org.jivesoftware.openfire.auth.InternalUnauthenticatedException;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.util.SystemProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * A simple filter that verifies authentication of HTTP requests.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class AuthFilter implements Filter
{
    private static final Logger Log = LoggerFactory.getLogger(AuthFilter.class);

    /**
     * The type of authentication that applies for requests processed by the webserver that is used for Jmx-to-Http bridging.
     */
    public static final SystemProperty<AuthType> JMXHTTPBRIDGE_WEBSERVER_AUTH_TYPE = SystemProperty.Builder.ofType(AuthType.class)
        .setKey("jmxhttpbridge.webserver.auth.type")
        .setDynamic(true)
        .setDefaultValue(AuthType.basic)
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * The value of the secret shared key, used when the webserver that is used for Jmx-to-Http bridging is configured
     * to use the {@link AuthType#secret} type of authentication.
     */
    public static final SystemProperty<String> JMXHTTPBRIDGE_WEBSERVER_AUTH_SECRET = SystemProperty.Builder.ofType(String.class)
        .setKey("jmxhttpbridge.webserver.auth.secret")
        .setDynamic(true)
        .setEncrypted(true)
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    public enum AuthType
    {
        /**
         * Authentication is not checked (anyone is allowed access).
         */
        none,

        /**
         * HTTP 'basic' authentication is used, that must match the credentials of an Openfire admin.
         */
        basic,

        /**
         * A shared secret is used to authenticate requests.
         */
        secret
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException
    {
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        // Let the preflight request through the authentication
        if ("OPTIONS".equals(request.getMethod())) {
            chain.doFilter(req, res);
            return;
        }

        final int statusCode = switch (JMXHTTPBRIDGE_WEBSERVER_AUTH_TYPE.getValue()) {
            case none -> HttpServletResponse.SC_OK;
            case basic -> doBasicAuth(request);
            case secret -> doSecretAuth(request);
            default -> {
                Log.warn("Authentication failed: Unexpected authentication type: {}", JMXHTTPBRIDGE_WEBSERVER_AUTH_TYPE.getValue());
                yield HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
            }
        };

        if (statusCode == HttpServletResponse.SC_OK) {
            chain.doFilter(req, res);
        } else {
            response.setStatus(statusCode);
            return;
        }
    }

    /**
     * Perform authentication using the 'basic authentication' protocol.
     *
     * @param request The HTTP request that is to be authenticated
     * @return An HTTP response status code, reflecting authentication success.
     */
    private int doBasicAuth(@Nonnull final HttpServletRequest request)
    {
        // Get the authentication passed in HTTP headers parameters
        final String auth = request.getHeader("authorization");
        if (auth == null) {
            Log.warn("Authentication failed: No authorization header found in request.");
            return HttpServletResponse.SC_UNAUTHORIZED;
        }

        final String[] usernameAndPassword = BasicAuth.decode(auth);

        if (usernameAndPassword == null || usernameAndPassword.length != 2) {
            Log.warn("Authentication failed: Username or password is not set");
            return HttpServletResponse.SC_UNAUTHORIZED;
        }

        final boolean userAdmin = AdminManager.getInstance().isUserAdmin(usernameAndPassword[0], true);

        if (!userAdmin) {
            Log.warn("Authentication failed: Provided User is not an admin: '{}'", usernameAndPassword[0]);
            return HttpServletResponse.SC_UNAUTHORIZED;
        }

        try {
            AuthFactory.authenticate(usernameAndPassword[0], usernameAndPassword[1]);
            Log.debug("Authentication for '{}' succeeded.", usernameAndPassword[0]);
            return HttpServletResponse.SC_OK;
        } catch (UnauthorizedException e) {
            Log.debug("Authentication for '{}' failed: incorrect credentials provided.", usernameAndPassword[0], e);
            return HttpServletResponse.SC_UNAUTHORIZED;
        } catch (ConnectionException e) {
            Log.warn("Authentication for '{}' failed: Openfire is not able to connect to the back-end users/group system.", usernameAndPassword[0], e);
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        } catch (InternalUnauthenticatedException e) {
            Log.warn("Authentication for '{}' failed: Openfire is not able to authenticate itself to the back-end users/group system.", usernameAndPassword[0], e);
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
    }

    /**
     * Perform authentication using the 'shared secret value'.
     *
     * @param request The HTTP request that is to be authenticated
     * @return An HTTP response status code, reflecting authentication success.
     */
    private int doSecretAuth(@Nonnull final HttpServletRequest request)
    {
        if (JMXHTTPBRIDGE_WEBSERVER_AUTH_SECRET.getValue() == null || JMXHTTPBRIDGE_WEBSERVER_AUTH_SECRET.getValue().isEmpty()) {
            Log.warn("Authentication failed: Openfire is configured to use 'secret' key authentication, but no secret key value is provided in Openfire's configuration!");
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        // Get the authentication passed in HTTP headers parameters
        final String auth = request.getHeader("authorization");
        if (auth == null) {
            Log.warn("Authentication failed: No authorization header found in request.");
            return HttpServletResponse.SC_UNAUTHORIZED;
        }

        if (!auth.equals(JMXHTTPBRIDGE_WEBSERVER_AUTH_SECRET.getValue())) {
            Log.warn("Authentication failed: Wrong secret key authorization: invalid secret value provided by end-user.");
            return HttpServletResponse.SC_UNAUTHORIZED;
        }
        Log.debug("Authentication succeeded.");
        return HttpServletResponse.SC_OK;
    }
}
