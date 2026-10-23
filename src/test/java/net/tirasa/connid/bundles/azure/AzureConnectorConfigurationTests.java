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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import net.tirasa.connid.bundles.azure.service.AzureClient;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.junit.jupiter.api.Test;

public class AzureConnectorConfigurationTests {

    private AzureConnectorConfiguration newConfiguration() {
        AzureConnectorConfiguration configuration = new AzureConnectorConfiguration();
        configuration.setClientId("client-id");
        configuration.setTenantId("tenant-id");
        configuration.setDomain("example.onmicrosoft.com");
        return configuration;
    }

    @Test
    public void validatesClientSecret() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setClientSecret("client-secret");
        assertDoesNotThrow(configuration::validate);
    }

    @Test
    public void validatesCertificate() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setCertificatePath("/path/to/certificate.pfx");
        configuration.setCertificatePassword("certificate-password");

        assertDoesNotThrow(configuration::validate);
    }

    @Test
    public void buildsSecretClient() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setClientSecret("client-secret");

        assertNotNull(new AzureClient(configuration).getAuthenticated().getGraphServiceClient());
    }

    @Test
    public void secretIgnoresLegacyCredentials() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setClientSecret("client-secret");
        configuration.setUsername("expired@example.com");
        configuration.setPassword("expired-password");
        configuration.setAuthority("invalid-authority");

        assertDoesNotThrow(configuration::validate);
        assertNotNull(new AzureClient(configuration).getAuthenticated().getGraphServiceClient());
    }

    @Test
    public void buildsLegacyClient() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setUsername("user@example.com");
        configuration.setPassword("password");
        configuration.setAuthority("https://login.microsoftonline.com/tenant-id");

        assertDoesNotThrow(configuration::validate);
        assertNotNull(new AzureClient(configuration).getAuthenticated().getGraphServiceClient());
    }

    @Test
    public void rejectsPartialLegacyCredentials() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setUsername("user@example.com");

        assertThrows(IllegalArgumentException.class, configuration::validate);
    }

    @Test
    public void legacyRequiresAuthority() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setUsername("user@example.com");
        configuration.setPassword("password");

        assertThrows(IllegalArgumentException.class, configuration::validate);
    }

    @Test
    public void buildsCertificateClient() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setCertificatePath("/path/to/certificate.pfx");

        assertNotNull(new AzureClient(configuration).getAuthenticated().getGraphServiceClient());
    }

    @Test
    public void certificateIgnoresLegacyCredentials() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setCertificatePath("/path/to/certificate.pfx");
        configuration.setUsername("expired@example.com");
        configuration.setPassword("expired-password");
        configuration.setAuthority("invalid-authority");

        assertDoesNotThrow(configuration::validate);
        assertNotNull(new AzureClient(configuration).getAuthenticated().getGraphServiceClient());
    }

    @Test
    public void certificateIgnoresPartialCredentials() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setCertificatePath("/path/to/certificate.pfx");
        configuration.setUsername("expired@example.com");

        assertDoesNotThrow(configuration::validate);
        assertNotNull(new AzureClient(configuration).getAuthenticated().getGraphServiceClient());
    }

    @Test
    public void rejectsMissingCredentials() {
        assertThrows(IllegalArgumentException.class, () -> newConfiguration().validate());
    }

    @Test
    public void rejectsConflictingCredentials() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setClientSecret("client-secret");
        configuration.setCertificatePath("/path/to/certificate.pfx");

        assertThrows(IllegalArgumentException.class, configuration::validate);
    }

    @Test
    public void rejectsPasswordWithoutCertificate() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setCertificatePassword("certificate-password");

        assertThrows(IllegalArgumentException.class, configuration::validate);
    }

    @Test
    public void secretIgnoresPartialCredentials() {
        AzureConnectorConfiguration configuration = newConfiguration();
        configuration.setClientSecret("client-secret");
        configuration.setUsername("user@example.com");

        assertDoesNotThrow(configuration::validate);
        assertNotNull(new AzureClient(configuration).getAuthenticated().getGraphServiceClient());
    }

    @Test
    public void preservesErrorCause() {
        RuntimeException cause = new RuntimeException("Failed to parse the certificate for the credential",
                new IOException("keystore password was incorrect"));

        ConnectorException exception = assertThrows(ConnectorException.class,
                () -> AzureUtils.handleGeneralError("Connection test failed", cause));

        assertEquals("Connection test failed", exception.getMessage());
        assertSame(cause, exception.getCause());
    }
}
