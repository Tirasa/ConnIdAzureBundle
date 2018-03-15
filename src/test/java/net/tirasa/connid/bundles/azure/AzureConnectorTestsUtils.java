package net.tirasa.connid.bundles.azure;

import com.microsoft.azure.management.resources.fluentcore.utils.SdkContext;
import java.util.Map;

import org.identityconnectors.common.logging.Log;

public class AzureConnectorTestsUtils {

    private static final Log LOGGER = Log.getLog(AzureConnectorTestsUtils.class);

    public static AzureConnectorConfiguration buildConfiguration(Map<String, String> configuration) {
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
                default:
                    LOGGER.warn("Occurrence of an non defined parameter");
                    break;
            }
        }
        return azureConnectorConfiguration;
    }

    public static boolean isConfigurationValid(final AzureConnectorConfiguration connectorConfiguration) {
        connectorConfiguration.validate();
        return true;
    }

    public static String createRandomName(final String namePrefix) {
        return SdkContext.randomResourceName(namePrefix, 30);
    }
}
