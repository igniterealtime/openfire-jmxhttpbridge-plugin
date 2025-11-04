<%--@elvariable id="errors" type="java.util.Map<String, Object>"--%>
<%--@elvariable id="csrf" type="java.lang.String"--%>
<%--@elvariable id="isJmxEnabled" type="java.lang.Boolean"--%>
<%--@elvariable id="port" type="java.lang.Integer"--%>
<%--@elvariable id="secureport" type="java.lang.Integer"--%>
<%--@elvariable id="authtype" type="org.igniterealtime.openfire.plugins.jmxhttpbridge.web.AuthFilter.AuthType"--%>
<%--@elvariable id="secretvalue" type="java.lang.String"--%>
<%@ taglib uri="admin" prefix="admin" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<html>
<head>
    <title><fmt:message key="admin.jmxhttpbridge.config.title"/></title>
    <meta name="pageID" content="jmxhttpbridge-config"/>
</head>
<body>

<admin:FlashMessage/>

<c:if test="${not isJmxEnabled}">
    <admin:infobox type="info">
        <fmt:message key="admin.jmxhttpbridge.config.info.jmx.disabled"/>
    </admin:infobox>
</c:if>

<c:choose>
    <c:when test="${not empty errors}">
        <c:forEach var="err" items="${errors}">
            <admin:infobox type="error">
                <c:choose>
                    <c:when test="${err.key eq 'csrf'}"><fmt:message key="global.csrf.failed" /></c:when>
                    <c:when test="${err.key eq 'port'}">
                        <fmt:message key="admin.jmxhttpbridge.config.error.port">
                            <fmt:param><fmt:message key="admin.jmxhttpbridge.config.webendpoint.port.label"/></fmt:param>
                        </fmt:message>
                    </c:when>
                    <c:when test="${err.key eq 'secureport'}">
                        <fmt:message key="admin.jmxhttpbridge.config.error.port">
                            <fmt:param><fmt:message key="admin.jmxhttpbridge.config.webendpoint.secureport.label"/></fmt:param>
                        </fmt:message>
                    </c:when>
                    <c:when test="${err.key eq 'authtype'}">
                        <fmt:message key="admin.jmxhttpbridge.config.error.authtype">
                            <fmt:param><fmt:message key="admin.jmxhttpbridge.config.authentication.boxtitle"/></fmt:param>
                        </fmt:message>
                    </c:when>
                    <c:when test="${err.key eq 'secretvalue'}">
                        <fmt:message key="admin.jmxhttpbridge.config.error.secretvalue">
                            <fmt:param><fmt:message key="admin.jmxhttpbridge.config.authentication.boxtitle"/></fmt:param>
                            <fmt:param><fmt:message key="admin.jmxhttpbridge.config.authentication.options.secret.label"/></fmt:param>
                            <fmt:param><fmt:message key="admin.jmxhttpbridge.config.authentication.options.secret.value.label"/></fmt:param>
                        </fmt:message>
                    </c:when>
                    <c:otherwise>
                        <c:if test="${not empty err.value}">
                            <fmt:message key="admin.error"/>: <c:out value="${err.value}"/>
                        </c:if>
                        (<c:out value="${err.key}"/>)
                    </c:otherwise>
                </c:choose>
            </admin:infobox>
        </c:forEach>
    </c:when>
    <c:when test="${param.success}">
        <admin:infoBox type="success">
            <fmt:message key="admin.jmxhttpbridge.config.success" />
        </admin:infoBox>
    </c:when>
</c:choose>
<c:if test="${(empty port) and (empty secureport)}">
    <admin:infoBox type="warning">
        <fmt:message key="admin.jmxhttpbridge.config.warning.inaccessible" />
    </admin:infoBox>
</c:if>

<p>
    <fmt:message key="admin.jmxhttpbridge.config.info" />
</p>
<c:if test="${(not empty port) or (not empty secureport)}">
    <p>
        <fmt:message key="admin.jmxhttpbridge.config.info.link"/>
    </p>
    <ul>
        <c:if test="${not empty port}">
            <li><a href="http://${admin:escapeHTMLTags(pageContext.request.serverName)}:${admin:escapeHTMLTags(port)}" target="_blank">http://${admin:escapeHTMLTags(pageContext.request.serverName)}:${admin:escapeHTMLTags(port)}</a></li>
        </c:if>
        <c:if test="${not empty secureport}">
            <li><a href="https://${admin:escapeHTMLTags(pageContext.request.serverName)}:${admin:escapeHTMLTags(secureport)}" target="_blank">https://${admin:escapeHTMLTags(pageContext.request.serverName)}:${admin:escapeHTMLTags(secureport)}</a></li>
        </c:if>
    </ul>
</c:if>

<form method="post" action="config.jsp">

    <fmt:message key="admin.jmxhttpbridge.config.webendpoint.boxtitle" var="webendpointboxtitle"/>
    <admin:contentBox title="${webendpointboxtitle}">
        <p><fmt:message key="admin.jmxhttpbridge.config.webendpoint.info" /></p>
        <table>
            <tr>
                <td>
                    <label for="port">
                        <strong><fmt:message key="admin.jmxhttpbridge.config.webendpoint.port.label" /></strong>
                    </label>
                </td>
                <td>
                    <input type="number" name="port" id="port" min="1" max="65535" value="${admin:escapeHTMLTags(port)}" />
                    <fmt:message key="admin.jmxhttpbridge.config.webendpoint.port.description" />
                </td>
            </tr>
            <tr>
                <td>
                    <label for="secureport">
                        <strong><fmt:message key="admin.jmxhttpbridge.config.webendpoint.secureport.label" /></strong>
                    </label>
                </td>
                <td>
                    <input type="number" name="secureport" id="secureport" min="1" max="65535" value="${admin:escapeHTMLTags(secureport)}" />
                    <fmt:message key="admin.jmxhttpbridge.config.webendpoint.secureport.description" />
                </td>
            </tr>
        </table>
    </admin:contentBox>

    <fmt:message key="admin.jmxhttpbridge.config.authentication.boxtitle" var="authenticationboxtitle"/>
    <admin:contentBox title="${authenticationboxtitle}">
        <p><fmt:message key="admin.jmxhttpbridge.config.authentication.info" /></p>
        <table>
            <tr>
                <td>
                    <input type="radio" name="authtype" value="none" id="none" ${authtype eq 'none' ? 'checked="checked"' : ''}/>
                </td>
                <td>
                    <label for="none">
                        <strong><fmt:message key="admin.jmxhttpbridge.config.authentication.options.none.label" /></strong>
                        - <fmt:message key="admin.jmxhttpbridge.config.authentication.options.none.description" />
                    </label>
                </td>
            </tr>
            <tr>
                <td>
                    <input type="radio" name="authtype" value="basic" id="basic" ${authtype eq 'basic' ? 'checked="checked"' : ''}/>
                </td>
                <td>
                    <label for="basic">
                        <strong><fmt:message key="admin.jmxhttpbridge.config.authentication.options.basic.label" /></strong>
                        - <fmt:message key="admin.jmxhttpbridge.config.authentication.options.basic.description" />
                    </label>
                </td>
            </tr>
            <tr>
                <td>
                    <input type="radio" name="authtype" value="secret" id="secret" ${authtype eq 'secret' ? 'checked="checked"' : ''}/>
                </td>
                <td>
                    <label for="secret">
                        <strong><fmt:message key="admin.jmxhttpbridge.config.authentication.options.secret.label" /></strong>
                        - <fmt:message key="admin.jmxhttpbridge.config.authentication.options.secret.description" />
                    </label>
                </td>
            </tr>
            <tr>
                <td>&nbsp;</td>
                <td>
                    <label for="secretvalue">
                        <fmt:message key="admin.jmxhttpbridge.config.authentication.options.secret.value.label" />
                    </label>
                    <input type="password" name="secretvalue" id="secretvalue" value="${admin:escapeHTMLTags(secretvalue)}"/>
                </td>
            </tr>
        </table>
    </admin:contentBox>

    <input type="hidden" name="csrf" value="${csrf}">
    <input type="submit" name="update" value="<fmt:message key="global.save_settings" />">
</form>

</body>
</html>
