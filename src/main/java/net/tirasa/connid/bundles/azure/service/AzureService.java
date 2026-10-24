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
package net.tirasa.connid.bundles.azure.service;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientCertificateCredential;
import com.azure.identity.ClientCertificateCredentialBuilder;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.PublicClientApplication;
import com.microsoft.aad.msal4j.UserNamePasswordParameters;
import com.microsoft.graph.serviceclient.GraphServiceClient;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import net.tirasa.connid.bundles.azure.AzureConnectorConfiguration;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import reactor.core.publisher.Mono;

public class AzureService {

    private static final Log LOG = Log.getLog(AzureService.class);

    public static final String METADATA_NAME_ID = "Name";

    public static final String METADATA_TYPE_ID = "Type";

    public static final String METADATA_NULLABLE_ID = "Nullable";

    public static final String METADATA_COLLECTION_VALUE = "Collection";

    public static final String USER_METADATA_TYPE_ID_VALUE = "User";

    public static final String GROUP_METADATA_TYPE_ID_VALUE = "Group";

    public static List<Map<String, String>> getMetadata(final String type) {
        return getXMLObjectFromAzureAD(type);
    }

    private static List<Map<String, String>> getXMLObjectFromAzureAD(final String type) {
        List<Map<String, String>> result = new ArrayList<>();

        // e.g. 
        // https://graph.windows.net/[DOMAIN_NAME].onmicrosoft.com/$metadata#directoryObjects/
        // Microsoft.DirectoryServices.User
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url(AzureConnectorConfiguration.DEFAULT_RESOURCE_URI + "/$metadata")
                    .addHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                    .addHeader("Accept-Encoding", "gzip, deflate, br")
                    .build();

            Response response = client.newCall(request).execute();
            InputStream xml = response.body().byteStream();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(xml);

            //optional, but recommended
            doc.getDocumentElement().normalize();

            result.addAll(getAttributesFromNodeList(doc, type));
        } catch (IOException | ParserConfigurationException | SAXException ex) {
            AzureUtils.handleGeneralError("While getting xml metadata object", ex);
        }

        return result;
    }

    private static List<Map<String, String>> getAttributesFromNodeList(final Document doc, final String objType) {
        List<Map<String, String>> list = new ArrayList<>();
        NodeList entityTypeList = doc.getElementsByTagName("EntityType");
        NodeList complexTypeList = doc.getElementsByTagName("ComplexType");

        for (int i = 0; i < entityTypeList.getLength(); i++) {
            Node nNode = entityTypeList.item(i);
            NodeList entitiesList = nNode.getChildNodes();
            Element eElement = (Element) entitiesList;
            String nodeName = eElement.getAttribute(METADATA_NAME_ID);

            if (StringUtil.isNotBlank(nodeName) && nodeName.equals(objType)) {
                for (int j = 0; j < entitiesList.getLength(); j++) {
                    Node subNode = entitiesList.item(j);

                    if (subNode.getNodeName().equals("Property")) {
                        eElement = (Element) subNode;
                        nodeName = eElement.getAttribute(METADATA_NAME_ID);
                        String nodeType = eElement.getAttribute(METADATA_TYPE_ID);
                        String nodeNullable = eElement.getAttribute(METADATA_NULLABLE_ID);

                        Map<String, String> map = new HashMap<>();
                        map.put(METADATA_NAME_ID, nodeName);
                        if (StringUtil.isNotBlank(nodeType)) {
                            map.put(METADATA_TYPE_ID, nodeType.replace("Edm.", ""));
                        }
                        if (StringUtil.isNotBlank(nodeNullable)) {
                            map.put(METADATA_NULLABLE_ID, nodeNullable);
                        }

                        list.add(map);
                    }
                }
            }
        }

        for (int i = 0; i < complexTypeList.getLength(); i++) {
            Node nNode = complexTypeList.item(i);
            Element eElement = (Element) nNode;
            String nodeName = eElement.getAttribute(METADATA_NAME_ID);

            if (StringUtil.isNotBlank(nodeName) && nodeName.equals(objType)) {
                String nodeType = eElement.getAttribute(METADATA_TYPE_ID);
                String nodeNullable = eElement.getAttribute(METADATA_NULLABLE_ID);

                Map<String, String> map = new HashMap<>();
                map.put(METADATA_NAME_ID, nodeName);
                if (StringUtil.isNotBlank(nodeType)) {
                    map.put(METADATA_TYPE_ID, nodeType.replace("Edm.", ""));
                }
                if (StringUtil.isNotBlank(nodeNullable)) {
                    map.put(METADATA_NULLABLE_ID, nodeNullable);
                }
                list.add(map);
            }
        }

        return list;
    }

    protected final AzureConnectorConfiguration config;

    private IAuthenticationResult authenticationResult;

    public AzureService(final AzureConnectorConfiguration config) {
        this.config = config;
        if (StringUtil.isNotBlank(config.getCertificatePath())) {
            LOG.info("Azure authentication configured: certificate");
        } else if (StringUtil.isNotBlank(config.getClientSecret())) {
            LOG.info("Azure authentication configured: client secret");
        } else {
            LOG.warn("Azure authentication configured: legacy username/password [deprecated]");
        }
    }

    public GraphServiceClient getGraphServiceClient() {
        try {
            GraphServiceClient client = new GraphServiceClient(getCredential(), config.getScopes());
            LOG.ok("Microsoft Graph client created");
            return client;
        } catch (RuntimeException e) {
            LOG.error(e, "Could not create Microsoft Graph client or its authentication credentials");
            throw e;
        }
    }

    private TokenCredential getCredential() {
        if (StringUtil.isNotBlank(config.getCertificatePath())) {
            LOG.ok("Selecting certificate authentication");
            return getCertificateCredential();
        }
        if (StringUtil.isNotBlank(config.getClientSecret())) {
            LOG.ok("Selecting client secret authentication");
            return getClientSecretCredential();
        }
        LOG.ok("Selecting legacy username/password authentication");
        return getLegacyCredential();
    }

    private ClientCertificateCredential getCertificateCredential() {
        LOG.ok("Building PFX certificate credential");
        ClientCertificateCredentialBuilder builder = new ClientCertificateCredentialBuilder()
                .clientId(config.getClientId())
                .tenantId(config.getTenantId())
                .pfxCertificate(config.getCertificatePath());
        if (StringUtil.isNotBlank(config.getCertificatePassword())) {
            builder.clientCertificatePassword(config.getCertificatePassword());
        }
        ClientCertificateCredential credential = builder.build();
        LOG.ok("Certificate credential built");
        return credential;
    }

    private ClientSecretCredential getClientSecretCredential() {
        LOG.ok("Building client secret credential");
        ClientSecretCredential credential = new ClientSecretCredentialBuilder()
                .clientId(config.getClientId())
                .clientSecret(config.getClientSecret())
                .tenantId(config.getTenantId())
                .build();
        LOG.ok("Client secret credential built");
        return credential;
    }

    private TokenCredential getLegacyCredential() {
        LOG.ok("Creating legacy credential");
        return request -> Mono.fromCallable(this::getLegacyToken);
    }

    private AccessToken getLegacyToken() {
        if (authenticationResult == null || StringUtil.isBlank(authenticationResult.accessToken())
                || new Date().after(authenticationResult.expiresOnDate())) {
            if (authenticationResult == null || StringUtil.isBlank(authenticationResult.accessToken())) {
                LOG.info("No cached token is available");
            } else {
                LOG.info("Renewing authentication token: cached token expired at {0}",
                        authenticationResult.expiresOnDate());
            }
            try {
                PublicClientApplication application = PublicClientApplication.builder(config.getClientId())
                        .authority(config.getAuthority())
                        .build();
                UserNamePasswordParameters parameters = UserNamePasswordParameters.builder(
                        Collections.singleton(config.getScopes()),
                        config.getUsername(),
                        config.getPassword().toCharArray()).build();
                authenticationResult = application.acquireToken(parameters).join();
                LOG.info("Authentication succeeded. Token expires at {0}", authenticationResult.expiresOnDate());
            } catch (MalformedURLException e) {
                LOG.error(e, "Authentication failed: invalid authority URL");
                throw new ConnectorException("Invalid authority for authentication", e);
            } catch (RuntimeException e) {
                LOG.error(e, "Could not acquire or renew the authentication token");
                throw e;
            }
        } else {
            LOG.ok("Reusing cached authentication token: expires at {0}", authenticationResult.expiresOnDate());
        }
        return new AccessToken(authenticationResult.accessToken(),
                authenticationResult.expiresOnDate().toInstant().atOffset(ZoneOffset.UTC));
    }
}
