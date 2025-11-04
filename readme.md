# JMX-HTTP Bridge Plugin

## Overview
The JMX / HTTP Bridge exposes Openfire's JMX interface over HTTP, allowing external monitoring and management tools to access metrics and runtime information without requiring a direct JMX connection.  
This makes it possible to integrate Openfire with HTTP- or JSON-based monitoring systems, even in environments where traditional JMX access is restricted or unavailable.

## CI Build Status

[![Build Status](https://github.com/igniterealtime/openfire-jmxhttpbridge-plugin/workflows/Java%20CI/badge.svg)](https://github.com/igniterealtime/openfire-jmxhttpbridge-plugin/actions)

## Reporting Issues

Issues may be reported to the [forums](https://discourse.igniterealtime.org) or via this repo's [Github Issues](https://github.com/igniterealtime/openfire-jmxhttpbridge-plugin).

## Features
- Exposes JMX data through a Jolokia-compatible HTTP interface.
- Provides machine-readable (JSON) responses suitable for integration with tools such as Prometheus, Grafana, or custom dashboards.
- Adds a configuration page to the Openfire Admin Console for easy setup.
- Supports authentication and HTTPS for secure access.
- Exposes all MBeans registered in the running JVM, including those defined by Openfire itself, other Openfire plugins, and third-party extensions.

## Installation
1. Copy the plugin's JAR file into Openfire's `plugins/` directory.
2. The plugin will be automatically deployed by Openfire.
3. After installation, a new entry labeled **"JMX / HTTP Bridge"** will appear in the Admin Console under *Server Settings*.

## Upgrading
1. Obtain the new version of the JMX / HTTP Bridge plugin.
2. Replace the existing plugin JAR file in the `plugins/` directory with the newer version.
3. Openfire will automatically redeploy the updated plugin.

## Configuration
The plugin adds a configuration page to the Openfire Admin Console, which allows you to configure:

- **Network port:** The TCP port on which the embedded webserver will listen for HTTP or HTTPS connections.
- **Authentication:** Whether access to the HTTP interface requires Openfire administrator credentials or a shared secret.

For this plugin to be useful, JMX support must be enabled in Openfire.  
This can be configured on the *Server Information* page in the Admin Console.

## Usage
Once enabled, the bridge exposes JMX data over HTTP at the root context path (`/`) of the embedded webserver.  
The interface is fully compatible with the [Jolokia API](https://jolokia.org/documentation.html).

Example endpoints include:

- `GET /` – Plugin index page.
- `POST /jolokia/` – Main Jolokia JSON endpoint.
- `GET /jolokia/read/<mbean>/<attribute>` – Read MBean attributes.
- `GET /health` – Simple health check.
- `GET /version` – Version and runtime info.

Example usage with `curl`:

```bash
curl -u admin:secret \
  "https://example.org:9291/jolokia/read/org.igniterealtime.openfire:type=Statistic,name=sessions"
