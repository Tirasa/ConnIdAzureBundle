/**
 * Copyright © 2018 ConnId (connid-dev@googlegroups.com)
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

    private String redirectURI = "https://login.live.com/oauth20_desktop.srf";

    private String resourceURI = "https://graph.windows.net";

    private String username;

    private String password;

    private String domain;

    public final static String DEFAULT_RESOURCE_URI = "https://graph.windows.net";

    @ConfigurationProperty(order = 1, displayMessageKey = "clientid.display",
            helpMessageKey = "clientid.help", required = true)
    public String getClientId() {
        return clientId;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    @ConfigurationProperty(order = 2, displayMessageKey = "authority.display",
            helpMessageKey = "authority.help", required = true)
    public String getAuthority() {
        return authority;
    }

    public void setAuthority(final String authority) {
        this.authority = authority;
    }

    @ConfigurationProperty(order = 3, displayMessageKey = "redirectURI.display",
            helpMessageKey = "redirectURI.help", required = false)
    public String getRedirectURI() {
        return redirectURI;
    }

    public void setRedirectURI(final String redirectURI) {
        this.redirectURI = redirectURI;
    }

    @ConfigurationProperty(order = 4, displayMessageKey = "resourceURI.display",
            helpMessageKey = "resourceURI.help", required = false)
    public String getResourceURI() {
        return resourceURI;
    }

    public void setResourceURI(String resourceURI) {
        this.resourceURI = resourceURI;
    }

    @ConfigurationProperty(order = 5, displayMessageKey = "username.display",
            helpMessageKey = "username.help", required = true)
    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    @ConfigurationProperty(order = 6, displayMessageKey = "password.display",
            helpMessageKey = "password.help", required = true, confidential = true)
    public String getPassword() {
        return password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    @ConfigurationProperty(order = 7, displayMessageKey = "domain.display",
            helpMessageKey = "domain.help", required = true)
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
    }

    @Override
    public void release() {
    }

}
