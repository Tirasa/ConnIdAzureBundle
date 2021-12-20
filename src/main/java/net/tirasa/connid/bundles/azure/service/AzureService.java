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

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.PublicClientApplication;
import com.microsoft.aad.msal4j.UserNamePasswordParameters;
import com.microsoft.graph.authentication.TokenCredentialAuthProvider;
import com.microsoft.graph.requests.GraphServiceClient;
import net.tirasa.connid.bundles.azure.AzureConnectorConfiguration;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class AzureService {

    private static final Log LOG = Log.getLog(AzureService.class);

    public final static String METADATA_NAME_ID = "Name";

    public final static String METADATA_TYPE_ID = "Type";

    public final static String METADATA_NULLABLE_ID = "Nullable";

    public final static String METADATA_COLLECTION_VALUE = "Collection";

    public static final String USER_METADATA_TYPE_ID_VALUE = "User";

    public static final String GROUP_METADATA_TYPE_ID_VALUE = "Group";

    protected final AzureConnectorConfiguration config;

    private IAuthenticationResult authenticationResult;

    public AzureService(final AzureConnectorConfiguration config) {
        this.config = config;
    }

    private void doAuth() {
        LOG.ok("Performing Azure account authentication");

        PublicClientApplication pca;
        try {
            pca = PublicClientApplication.builder(config.getClientId())
                    .authority(config.getAuthority())
                    .build();

            UserNamePasswordParameters parameters = UserNamePasswordParameters
                    .builder(Collections.singleton(config.getScopes()), config.getUsername(),
                            config.getPassword().toCharArray()).build();

            authenticationResult = pca.acquireToken(parameters).join();
            LOG.ok("==username/password flow succeeded");

        } catch (MalformedURLException ex) {
            AzureUtils.handleGeneralError("While performing Azure authentication", ex);
        }
    }

    protected void checkAuth() {
        if (!isAuthenticated()) {
            doAuth();
        }
        checkTokenExpiry();
    }

    private boolean isAuthenticated() {
        return authenticationResult != null
                && StringUtil.isNotBlank(authenticationResult.accessToken());
    }

    private void checkTokenExpiry() {
        Date expireOnDate = authenticationResult.expiresOnDate();
        Date currentDate = new Date();
        if (currentDate.after(expireOnDate)) {
            LOG.ok("Token expired! Refreshing...");
            doAuth();
        }
    }

    public GraphServiceClient getGraphServiceClient() {
        checkAuth();

        final ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
                .clientId(config.getClientId())
                .clientSecret(config.getClientSecret())
                .tenantId(config.getTenantId())
                .build();

        final TokenCredentialAuthProvider tokenCredAuthProvider =
                new TokenCredentialAuthProvider(Collections.singletonList(config.getScopes()), clientSecretCredential);

        return GraphServiceClient.builder().authenticationProvider(tokenCredAuthProvider).buildClient();
    }

    public static List<Map<String, String>> getMetadata(final String type) {
        return getXMLObjectFromAzureAD(type);
    }

    private static List<Map<String, String>> getXMLObjectFromAzureAD(final String type) {
        List<Map<String, String>> result = new ArrayList<>();

        // e.g. 
        // https://graph.windows.net/[DOMAIN_NAME].onmicrosoft.com/$metadata#directoryObjects/Microsoft.DirectoryServices.User
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

}
