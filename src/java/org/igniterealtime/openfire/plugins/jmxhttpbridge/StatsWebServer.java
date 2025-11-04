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
package org.igniterealtime.openfire.plugins.jmxhttpbridge;

import org.eclipse.jetty.ee8.webapp.WebAppContext;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.util.resource.ResourceFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.igniterealtime.openfire.plugins.jmxhttpbridge.web.AuthFilter;
import org.jivesoftware.admin.ContentSecurityPolicyFilter;
import org.jivesoftware.openfire.ConnectionManager;
import org.jivesoftware.openfire.JMXManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.keystore.CertificateStore;
import org.jivesoftware.openfire.keystore.IdentityStore;
import org.jivesoftware.openfire.spi.ConnectionConfiguration;
import org.jivesoftware.openfire.spi.ConnectionType;
import org.jivesoftware.openfire.spi.EncryptionArtifactFactory;
import org.jivesoftware.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.net.URL;
import java.nio.file.Path;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.TimerTask;

/**
 * The embedded webserver that handles HTTP requests for JMX data.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class StatsWebServer
{
    private static final Logger Log = LoggerFactory.getLogger(StatsWebServer.class);

    private static boolean IS_RESTART_NEEDED = false;

    /**
     * A quick&dirty solution that causes the webserver to restart after a (potentially set of) configuration change
     * have been applied.
     *
     * The delay that's introduced intends to reduce the amount of restarts that occur when multiple configuration
     * changes are applied at once.
     */
    private synchronized static void SCHEDULE_RESTART()
    {
        if (!IS_RESTART_NEEDED) {
            IS_RESTART_NEEDED = true;
            TaskEngine.getInstance().schedule(new TimerTask() {
                @Override
                public void run() {
                    // TODO instead of restarting the entire plugin, consider restarting just the embedded webserver.
                    Log.info("Restarting web server to apply changes...");
                    final PluginManager pluginManager = XMPPServer.getInstance().getPluginManager();
                    final Plugin plugin = pluginManager.getPluginByName(JmxHttpBridgePlugin.PLUGIN_NAME).orElse(null);
                    pluginManager.reloadPlugin(pluginManager.getCanonicalName(plugin));
                }
            }, Duration.ofSeconds(5));
        }
    }
    
    /**
     * Duration of the maximum duration of gracefully stopping the embedded webserver that is used for Jmx-to-Http bridging.
     */
    public static final SystemProperty<Duration> JMXHTTPBRIDGE_WEBSERVER_STOP_TIMEOUT = SystemProperty.Builder.ofType(Duration.class)
        .setKey("jmxhttpbridge.webserver.stop-timeout")
        .setChronoUnit(ChronoUnit.MILLIS)
        .setDynamic(true)
        .setDefaultValue(Duration.ofSeconds(5))
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * Enable / Disable parsing a 'X-Forwarded-For' style HTTP header of HTTP requests in the webserver that is used for Jmx-to-Http bridging.
     */
    public static final SystemProperty<Boolean> JMXHTTPBRIDGE_WEBSERVER_FORWARDED = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("jmxhttpbridge.webserver.forwarded.enabled")
        .setDynamic(false)
        .setDefaultValue(false)
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * The HTTP header name for 'forwarded for' used by the webserver that is used for Jmx-to-Http bridging.
     */
    public static final SystemProperty<String> JMXHTTPBRIDGE_WEBSERVER_FORWARDED_FOR = SystemProperty.Builder.ofType(String.class)
        .setKey("jmxhttpbridge.webserver.forwarded.for.header")
        .setDynamic(false)
        .setDefaultValue(HttpHeader.X_FORWARDED_FOR.toString())
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * The HTTP header name for 'forwarded server' used by the webserver that is used for Jmx-to-Http bridging.
     */
    public static final SystemProperty<String> JMXHTTPBRIDGE_WEBSERVER_FORWARDED_SERVER = SystemProperty.Builder.ofType(String.class)
        .setKey("jmxhttpbridge.webserver.forwarded.server.header")
        .setDynamic(false)
        .setDefaultValue(HttpHeader.X_FORWARDED_SERVER.toString())
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * The HTTP header name for 'forwarded hosts' used by the webserver that is used for Jmx-to-Http bridging.
     */
    public static final SystemProperty<String> JMXHTTPBRIDGE_WEBSERVER_FORWARDED_HOST = SystemProperty.Builder.ofType(String.class)
        .setKey("jmxhttpbridge.webserver.forwarded.host.header")
        .setDynamic(false)
        .setDefaultValue(HttpHeader.X_FORWARDED_HOST.toString())
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * Sets a forced valued for the host header used by the webserver that is used for Jmx-to-Http bridging.
     */
    public static final SystemProperty<String> JMXHTTPBRIDGE_WEBSERVER_FORWARDED_HOST_NAME = SystemProperty.Builder.ofType(String.class)
        .setKey("jmxhttpbridge.webserver.forwarded.host.name")
        .setDynamic(false)
        .setDefaultValue(null)
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * Enable / Disable adding a 'Content-Security-Policy' HTTP header to the response to requests made against the webserver that is used for Jmx-to-Http bridging.
     */
    public static final SystemProperty<Boolean> JMXHTTPBRIDGE_WEBSERVER_CONTENT_SECURITY_POLICY_ENABLED = SystemProperty.Builder.ofType(Boolean.class)
        .setKey("jmxhttpbridge.webserver.CSP.enabled")
        .setDynamic(true)
        .setDefaultValue(true)
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * The header value when adding a 'Content-Security-Policy' HTTP header to the response to requests made against the webserver that is used for Jmx-to-Http bridging.
     */
    public static final SystemProperty<String> JMXHTTPBRIDGE_WEBSERVER_CONTENT_SECURITY_POLICY_RESPONSEVALUE = SystemProperty.Builder.ofType(String.class)
        .setKey("jmxhttpbridge.webserver.CSP.responsevalue")
        .setDynamic(true)
        .setDefaultValue("default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; base-uri 'self'; form-action 'self'; img-src 'self' igniterealtime.org;")
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * The TCP port that the webserver that is used for Jmx-to-Http bridging will use to listen for HTTP (non-encrypted) requests.
     */
    public static final SystemProperty<Integer> JMXHTTPBRIDGE_WEBSERVER_PORT = SystemProperty.Builder.ofType(Integer.class)
        .setKey("jmxhttpbridge.webserver.port")
        .setDynamic(true)
        .setDefaultValue(9290)
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * The TCP port that the webserver that is used for Jmx-to-Http bridging will use to listen for HTTPS (encrypted) requests.
     */
    public static final SystemProperty<Integer> JMXHTTPBRIDGE_WEBSERVER_PORT_SECURE = SystemProperty.Builder.ofType(Integer.class)
        .setKey("jmxhttpbridge.webserver.securePort")
        .setDynamic(true)
        .setDefaultValue(9291)
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    /**
     * The number of threads allocated to each connector/port of the webserver that is used for Jmx-to-Http bridging.
     */
    public static final SystemProperty<Integer> JMXHTTPBRIDGE_WEBSERVER_SERVER_THREADS = SystemProperty.Builder.ofType(Integer.class)
        .setKey("jmxhttpbridge.webserver.serverThreads")
        .setDynamic(true)
        .setDefaultValue(2)
        .addListener(v-> StatsWebServer.SCHEDULE_RESTART())
        .setPlugin(JmxHttpBridgePlugin.PLUGIN_NAME)
        .build();

    private final Path webappDir;
    private Server webserver;
    private ContextHandlerCollection contexts;
    private CertificateEventListener certificateListener;

    public StatsWebServer(@Nonnull final Path webappDir)
    {
        this.webappDir = webappDir;
    }

    /**
     * Starts the Jetty instance.
     */
    protected synchronized void startup()
    {
        IS_RESTART_NEEDED = false;

        // Add listener for certificate events
        certificateListener = new CertificateListener();
        CertificateManager.addListener(certificateListener);

        final QueuedThreadPool tp = new QueuedThreadPool();
        tp.setName("Jetty-QTP-JmxHttpBridge");

        webserver = new Server(tp);

        if (JMXManager.isEnabled()) {
            JMXManager jmx = JMXManager.getInstance();
            webserver.addBean(jmx.getContainer());
        }

        final Duration stopTimeout = JMXHTTPBRIDGE_WEBSERVER_STOP_TIMEOUT.getValue();
        webserver.setStopTimeout(stopTimeout == null || stopTimeout.isNegative() ? 0 : stopTimeout.toMillis());

        // Create connector for http traffic if it's enabled.
        if (JMXHTTPBRIDGE_WEBSERVER_PORT.getValue() > 0)
        {
            final HttpConfiguration httpConfig = new HttpConfiguration();

            // Do not send Jetty info in HTTP headers
            httpConfig.setSendServerVersion( false );
            configureProxiedConnector(httpConfig);

            final ServerConnector httpConnector = new ServerConnector(webserver, null, null, null, -1, JMXHTTPBRIDGE_WEBSERVER_SERVER_THREADS.getValue(), new HttpConnectionFactory(httpConfig));

            // Listen on a specific network interface if it has been set.
            String bindInterface = getBindInterface();
            httpConnector.setHost(bindInterface);
            httpConnector.setPort(JMXHTTPBRIDGE_WEBSERVER_PORT.getValue());
            webserver.addConnector(httpConnector);
        }

        // Create a connector for https traffic if it's enabled.
        try {
            IdentityStore identityStore = null;
            if (XMPPServer.getInstance().getCertificateStoreManager() == null) {
                Log.warn( "CertificateStoreManager has not been initialized yet. HTTPS will be unavailable." );
            } else {
                identityStore = XMPPServer.getInstance().getCertificateStoreManager().getIdentityStore( ConnectionType.WEBADMIN );
            }
            if (identityStore != null && JMXHTTPBRIDGE_WEBSERVER_PORT_SECURE.getValue() > 0 )
            {
                if ( identityStore.getAllCertificates().isEmpty() )
                {
                    Log.warn( "Identity store does not have any certificates. HTTPS will be unavailable." );
                }
                else
                {
                    if ( !identityStore.containsDomainCertificate() )
                    {
                        Log.warn( "Using certificates but they are not valid for the hosted domain" );
                    }

                    final ConnectionManager connectionManager = XMPPServer.getInstance().getConnectionManager();
                    final ConnectionConfiguration configuration = connectionManager.getListener( ConnectionType.WEBADMIN, true ).generateConnectionConfiguration();
                    final SslContextFactory.Server sslContextFactory = new EncryptionArtifactFactory( configuration ).getSslContextFactory();

                    final HttpConfiguration httpsConfig = new HttpConfiguration();
                    httpsConfig.setSendServerVersion( false );
                    httpsConfig.setSecureScheme( "https" );
                    httpsConfig.setSecurePort( JMXHTTPBRIDGE_WEBSERVER_PORT_SECURE.getValue() );
                    SecureRequestCustomizer secureRequestCustomizer = new SecureRequestCustomizer();
                    secureRequestCustomizer.setSniHostCheck(sslContextFactory.isSniRequired());
                    httpsConfig.addCustomizer( secureRequestCustomizer );
                    configureProxiedConnector(httpsConfig);

                    final HttpConnectionFactory httpConnectionFactory = new HttpConnectionFactory( httpsConfig );
                    final SslConnectionFactory sslConnectionFactory = new SslConnectionFactory( sslContextFactory, org.eclipse.jetty.http.HttpVersion.HTTP_1_1.toString() );

                    final ServerConnector httpsConnector = new ServerConnector(webserver, null, null, null, -1, JMXHTTPBRIDGE_WEBSERVER_SERVER_THREADS.getValue(), sslConnectionFactory, httpConnectionFactory );
                    final String bindInterface = getBindInterface();
                    httpsConnector.setHost(bindInterface);
                    httpsConnector.setPort(JMXHTTPBRIDGE_WEBSERVER_PORT_SECURE.getValue());
                    webserver.addConnector(httpsConnector);
                }
            }
        }
        catch ( Exception e )
        {
            Log.error( "An exception occurred while trying to make available the webserver that is used for Jmx-to-Http bridging via HTTPS.", e );
        }

        // Make sure that at least one connector was registered.
        if (webserver.getConnectors() == null || webserver.getConnectors().length == 0) {
            webserver = null;
            // Log warning.
            Log.warn(LocaleUtils.getLocalizedString("No HTTP ports configured. HTTP requests will not be processed."));
            return;
        }

        createWebAppContext();

        Handler.Sequence collection = new Handler.Sequence();
        webserver.setHandler(collection);
        collection.setHandlers(contexts, new DefaultHandler());

        try {
            webserver.start(); // excludes initialised
            logAdminConsolePorts();
        }
        catch (Exception e) {
            Log.error("Could not start the webserver that is used for Jmx-to-Http bridging", e);
        }
    }

    /**
     * Shuts down the Jetty server.
     * */
    protected void shutdown()
    {
        // Remove listener for certificate events
        if (certificateListener != null) {
            CertificateManager.removeListener(certificateListener);
        }
        try {
            if (webserver != null && webserver.isRunning()) {
                webserver.stop();
            }
        }
        catch (Exception e) {
            Log.warn("Error stopping the webserver that is used for Jmx-to-Http bridging", e);
        }

        if (contexts != null ) {
            try {
                contexts.stop();
                contexts.destroy();
            } catch ( Exception e ) {
                Log.warn("Error stopping the webserver that is used for Jmx-to-Http bridging", e);
            }
        }
        webserver = null;
        contexts = null;
    }

    private void configureProxiedConnector(HttpConfiguration httpConfig)
    {
        // Check to see if we are deployed behind a proxy
        // Refer to http://eclipse.org/jetty/documentation/current/configuring-connectors.html
        if (JMXHTTPBRIDGE_WEBSERVER_FORWARDED.getValue()) {
            ForwardedRequestCustomizer customizer = new ForwardedRequestCustomizer();
            // default: "X-Forwarded-For"
            String forwardedForHeader = JMXHTTPBRIDGE_WEBSERVER_FORWARDED_FOR.getValue();
            if (forwardedForHeader != null) {
                customizer.setForwardedForHeader(forwardedForHeader);
            }
            // default: "X-Forwarded-Server"
            String forwardedServerHeader = JMXHTTPBRIDGE_WEBSERVER_FORWARDED_SERVER.getValue();
            if (forwardedServerHeader != null) {
                customizer.setForwardedServerHeader(forwardedServerHeader);
            }
            // default: "X-Forwarded-Host"
            String forwardedHostHeader = JMXHTTPBRIDGE_WEBSERVER_FORWARDED_HOST.getValue();
            if (forwardedHostHeader != null) {
                customizer.setForwardedHostHeader(forwardedHostHeader);
            }
            // default: none
            String hostName = JMXHTTPBRIDGE_WEBSERVER_FORWARDED_HOST_NAME.getValue();
            if (hostName != null) {
                customizer.setHostHeader(hostName);
            }

            httpConfig.addCustomizer(customizer);
        }
    }

    /**
     * Restart the webserver.
     */
    public void restart() {
        try {
            shutdown();
            startup();
        }
        catch (Exception e) {
            Log.error("An exception occurred while restarting the webserver that is used for Jmx-to-Http bridging", e);
        }
    }

    private void createWebAppContext()
    {
        contexts = new ContextHandlerCollection();

        WebAppContext context = new WebAppContext(contexts, webappDir.resolve("classes").toAbsolutePath().toString(), "/");

        context.setInitParameter("org.eclipse.jetty.servlet.Default.dirAllowed", "false");
        context.setClassLoader(Thread.currentThread().getContextClassLoader());
        final URL classes = getClass().getProtectionDomain().getCodeSource().getLocation();
        final ResourceFactory resourceFactory = ResourceFactory.of(context);
        context.getMetaData().setWebInfClassesResources(Collections.singletonList(resourceFactory.newResource(classes)));

        // Add CSP headers for all HTTP responses (errors, etc.)
        context.addFilter(AdminContentSecurityPolicyFilter.class, "/*", null);
        context.addFilter(AuthFilter.class, "/jolokia/*", null);
        context.addFilter(AuthFilter.class, "/health/*", null);
        context.addFilter(AuthFilter.class, "/version/*", null);

        // The index.html includes a redirect to the index.jsp and doesn't bypass
        // the context security when in development mode
        context.setWelcomeFiles(new String[]{"index.html"});
    }

    /**
     * Returns {@code null} if the webserver that is used for Jmx-to-Http bridging will be available in all network
     * interfaces of this machine or a String representing the only interface where the webserver will be available.
     *
     * @return String representing the only interface where the webserver will be available or null if it will be
     * available in all interfaces.
     */
    public String getBindInterface() {
        // This is an exact copy of this method in the admin console plugin class.
        String adminInterfaceName = JiveGlobals.getXMLProperty("adminConsole.interface");
        String globalInterfaceName = JiveGlobals.getXMLProperty("network.interface");
        String bindInterface = null;
        if (adminInterfaceName != null && !adminInterfaceName.trim().isEmpty()) {
            bindInterface = adminInterfaceName;
        }
        else if (globalInterfaceName != null && !globalInterfaceName.trim().isEmpty()) {
            bindInterface = globalInterfaceName;
        }
        return bindInterface;
    }

    private void logAdminConsolePorts()
    {
        // Log what ports the admin console is running on.
        final String hostname = getBindInterface() == null ?
            XMPPServer.getInstance().getServerInfo().getXMPPDomain() :
            getBindInterface();

        for (Connector connector : webserver.getConnectors()) {
            if (((ServerConnector) connector).getPort() == JMXHTTPBRIDGE_WEBSERVER_PORT.getValue()) {
                Log.info("The webserver that is used for Jmx-to-Http bridging is listening on http://{}:{}", hostname, JMXHTTPBRIDGE_WEBSERVER_PORT.getValue());
            }
            else if (((ServerConnector) connector).getPort() == JMXHTTPBRIDGE_WEBSERVER_PORT_SECURE.getValue()) {
                Log.info("The webserver that is used for Jmx-to-Http bridging is listening on https://{}:{}", hostname, JMXHTTPBRIDGE_WEBSERVER_PORT_SECURE.getValue());
            }
        }
    }

    /**
     * Listens for security certificates being created and destroyed so we can track when the webserver needs to be restarted.
     */
    private static class CertificateListener implements CertificateEventListener
    {
        @Override
        public void storeContentChanged( CertificateStore store )
        {
            Log.info("Scheduling restart of webserver. Certificate changes detected.");
            IS_RESTART_NEEDED = true;
        }
    }

    public static class AdminContentSecurityPolicyFilter extends ContentSecurityPolicyFilter
    {
        public AdminContentSecurityPolicyFilter()
        {
            super(JMXHTTPBRIDGE_WEBSERVER_CONTENT_SECURITY_POLICY_ENABLED, JMXHTTPBRIDGE_WEBSERVER_CONTENT_SECURITY_POLICY_RESPONSEVALUE);
        }
    }
}
