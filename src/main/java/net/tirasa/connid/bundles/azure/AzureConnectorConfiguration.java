package net.tirasa.connid.bundles.azure;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;
import org.identityconnectors.framework.spi.StatefulConfiguration;

/**
 *
 * Connector configuration class. It contains all the needed methods for
 * processing the connector configuration.
 *
 */
public class AzureConnectorConfiguration extends AbstractConfiguration implements StatefulConfiguration {

    private String clientId;

    private String authority;

    private String redirectURI;

    private String resourceURI;

    private String username;

    private String password;

    private String domain;

    public final static String DEFAULT_RESOURCE_URI = "https://graph.windows.net";

    public final static String DEFAULT_REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf";

    @ConfigurationProperty(order = 1, displayMessageKey = "clientid.display",
            groupMessageKey = "basic.group", helpMessageKey = "clientid.help", required = true,
            confidential = false)
    public String getClientId() {
        return clientId;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    @ConfigurationProperty(order = 2, displayMessageKey = "authority.display",
            groupMessageKey = "basic.group", helpMessageKey = "authority.help", required = true,
            confidential = false)
    public String getAuthority() {
        return authority;
    }

    public void setAuthority(final String authority) {
        this.authority = authority;
    }

    @ConfigurationProperty(order = 3, displayMessageKey = "redirectURI.display",
            groupMessageKey = "basic.group", helpMessageKey = "redirectURI.help", required = false,
            confidential = false)
    public String getRedirectURI() {
        return redirectURI;
    }

    public void setRedirectURI(final String redirectURI) {
        this.redirectURI = redirectURI;
    }

    @ConfigurationProperty(order = 4, displayMessageKey = "resourceURI.display",
            groupMessageKey = "basic.group", helpMessageKey = "resourceURI.help", required = false,
            confidential = false)
    public String getResourceURI() {
        return resourceURI;
    }

    public void setResourceURI(String resourceURI) {
        this.resourceURI = resourceURI;
    }

    @ConfigurationProperty(order = 5, displayMessageKey = "username.display",
            groupMessageKey = "basic.group", helpMessageKey = "username.help", required = true,
            confidential = false)
    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    @ConfigurationProperty(order = 6, displayMessageKey = "password.display",
            groupMessageKey = "basic.group", helpMessageKey = "password.help", required = true,
            confidential = true)
    public String getPassword() {
        return password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    @ConfigurationProperty(order = 7, displayMessageKey = "domain.display",
            groupMessageKey = "basic.group", helpMessageKey = "domain.help", required = true,
            confidential = false)
    public String getDomain() {
        return domain;
    }

    public void setDomain(final String domain) {
        this.domain = domain;
    }

    @Override
    public void validate() {
        if (StringUtil.isBlank(authority)) {
            throw new IllegalArgumentException("Authority cannot be null or empty.");
        }
        if (StringUtil.isBlank(clientId)) {
            throw new IllegalArgumentException("Client Id cannot be null or empty.");
        }
        if (StringUtil.isBlank(username)) {
            throw new IllegalArgumentException("Username cannot be null or empty.");
        }
        if (StringUtil.isBlank(password)) {
            throw new IllegalArgumentException("Password Id cannot be null or empty.");
        }
        if (StringUtil.isBlank(domain)) {
            throw new IllegalArgumentException("Domain Id cannot be null or empty.");
        }
        if (StringUtil.isBlank(redirectURI)) {
            redirectURI = DEFAULT_REDIRECT_URI;
        }
        if (StringUtil.isBlank(resourceURI)) {
            resourceURI = DEFAULT_RESOURCE_URI;
        }
    }

    @Override
    public void release() {
    }

}
