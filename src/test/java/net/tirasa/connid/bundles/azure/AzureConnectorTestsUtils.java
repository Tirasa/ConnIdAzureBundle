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

import java.util.Map;
import org.identityconnectors.common.logging.Log;

public final class AzureConnectorTestsUtils {

    private static final Log LOG = Log.getLog(AzureConnectorTestsUtils.class);

    public static AzureConnectorConfiguration buildConfiguration(final Map<String, String> configuration) {
        AzureConnectorConfiguration azureConnectorConfiguration = new AzureConnectorConfiguration();

        for (Map.Entry<String, String> entry : configuration.entrySet()) {

            switch (entry.getKey()) {
                case "oauth2.clientId":
                    azureConnectorConfiguration.setClientId(entry.getValue());
                    break;
                case "oauth2.authority":
                    azureConnectorConfiguration.setAuthority(entry.getValue());
                    break;
                case "oauth2.domain":
                    azureConnectorConfiguration.setDomain(entry.getValue());
                    break;
                case "oauth2.password":
                    azureConnectorConfiguration.setPassword(entry.getValue());
                    break;
                case "oauth2.redirectURI":
                    azureConnectorConfiguration.setRedirectURI(entry.getValue());
                    break;
                case "oauth2.resourceURI":
                    azureConnectorConfiguration.setResourceURI(entry.getValue());
                    break;
                case "oauth2.username":
                    azureConnectorConfiguration.setUsername(entry.getValue());
                    break;
                case "oauth2.tenantId":
                    azureConnectorConfiguration.setTenantId(entry.getValue());
                    break;
                case "oauth2.clientSecret":
                    azureConnectorConfiguration.setClientSecret(entry.getValue());
                    break;
                case "oauth2.scopes":
                    azureConnectorConfiguration.setScopes(entry.getValue());
                    break;
                case "oauth2.userAttributesToGet":
                    azureConnectorConfiguration.setUserAttributesToGet(entry.getValue());
                    break;
                case "oauth2.groupAttributesToGet":
                    azureConnectorConfiguration.setGroupAttributesToGet(entry.getValue());
                    break;
                case "oauth2.restoreItems":
                    azureConnectorConfiguration.setRestoreItems(Boolean.parseBoolean(entry.getValue()));
                    break;
                default:
                    LOG.warn("Occurrence of an non defined parameter");
                    break;
            }
        }
        return azureConnectorConfiguration;
    }

    public static boolean isConfigurationValid(final AzureConnectorConfiguration connectorConfiguration) {
        connectorConfiguration.validate();
        return true;
    }

    private AzureConnectorTestsUtils() {
        // private constructor for static utility class
    }
}
