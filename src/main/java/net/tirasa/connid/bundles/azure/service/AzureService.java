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

import com.fasterxml.jackson.databind.JsonNode;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import net.tirasa.connid.bundles.azure.AzureConnectorConfiguration;
import net.tirasa.connid.bundles.azure.dto.AzureError;
import net.tirasa.connid.bundles.azure.utils.AzureAttributes;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.cxf.jaxrs.client.WebClient;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class AzureService {

    private static final Log LOG = Log.getLog(AzureService.class);

    private final static String API_VERSION = "1.6";

    private final static String API_VERSION_PARAM = "api-version";

    private final static String ODATA_ERROR_ID = "odata.error";

    private final static String ODATA_NEXTPAGE_ID = "odata.nextLink";

    public final static String SKIP_TOKEN_ID = "$skiptoken=";

    public final static String METADATA_NAME_ID = "Name";

    public final static String METADATA_TYPE_ID = "Type";

    public final static String METADATA_NULLABLE_ID = "Nullable";

    public final static String METADATA_COLLECTION_VALUE = "Collection";

    public static final String USER_METADATA_TYPE_ID_VALUE = "User";

    public static final String GROUP_METADATA_TYPE_ID_VALUE = "Group";

    public static final String ACCEPT_HEADER = "Accept";

    private final String domain;

    private final String authority;

    private final String clientId;

    private final String username;

    private final String password;

    private final String resourceURI;

    private String pagedResultsSkipToken;

    private AuthenticationResult authenticationResult;

    public AzureService(final String authority, final String clientId, final String username, final String password,
            final String resourceURI, final String domain) {
        this.authority = authority;
        this.clientId = clientId;
        this.username = username;
        this.password = password;
        this.resourceURI = resourceURI;
        this.domain = domain;
    }

    private void doAuth() {
        LOG.ok("Performing Azure account authentication");

        AuthenticationContext context;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);

            context = new AuthenticationContext(authority, false, service);
            Future<AuthenticationResult> future = context.acquireToken(
                    resourceURI,
                    clientId,
                    username,
                    password,
                    null);

            authenticationResult = future.get();
        } catch (InterruptedException | ExecutionException | MalformedURLException ex) {
            AzureUtils.handleGeneralError("While performing Azure authentication", ex);
        } finally {
            if (service != null) {
                service.shutdown();
            }
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
                && StringUtil.isNotBlank(authenticationResult.getAccessToken());
    }

    private void checkTokenExpiry() {
        Date expireOnDate = authenticationResult.getExpiresOnDate();
        Date currentDate = new Date();
        if (currentDate.after(expireOnDate)) {
            LOG.info("Token expired! Refreshing...");
            doAuth();
        }
    }

    public WebClient getWebclient(final String subDomain, final String parameters) {
        checkAuth();

        WebClient webClient = WebClient
                .create(resourceURI)
                .type(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + authenticationResult.getAccessToken())
                .path(domain)
                .path(subDomain)
                .query(API_VERSION_PARAM, API_VERSION);

        if (StringUtil.isNotBlank(parameters)) {
            webClient.query(encodeURL(parameters));
        }

        return webClient;
    }

    public JsonNode doGetFromAzure(final WebClient webClient) {
        LOG.ok("webClient current URL : {0}", webClient.getCurrentURI());
        JsonNode result = null;

        try {
            Response response = webClient.get();
            String responseAsString = response.readEntity(String.class);
            result = AzureUtils.MAPPER.readTree(responseAsString);

            checkAzureErrors(result, response);

            // case of paged results
            JsonNode nextLink = result.get(ODATA_NEXTPAGE_ID);
            if (nextLink != null && !nextLink.isNull()) {
                pagedResultsSkipToken = StringUtils.substringAfter(nextLink.asText(), SKIP_TOKEN_ID);
            }

            // case of multiple results or no results
            if (result.has("value") && !result.get("value").isNull()) {
                result = result.get("value");
            }

        } catch (IOException ex) {
            LOG.error(ex, "While retrieving data from Azure AD service");
        }

        return result;
    }

    public List<String> extractUsersFromGroupMemberships(final JsonNode json) {
        List<String> userIds = new ArrayList<>();

        if (json != null) {
            JsonNode urls = json.has("value") ? json.get("value") : json;
            if (urls != null && !urls.isNull() && urls.isArray()) {
                Iterator<JsonNode> subAttrsNode = urls.elements();
                while (subAttrsNode.hasNext()) {
                    JsonNode entry = subAttrsNode.next();
                    try {
                        String url = entry.get("url").asText();
                        WebClient webClient = getWebclient(url, null);
                        if (url.contains(".Group")) {
                            JsonNode obj = doGetFromAzure(webClient);
                            if (obj != null) {
                                String userId = obj.get(AzureAttributes.GROUP_ID).asText();
                                if (StringUtil.isNotBlank(userId)) {
                                    userIds.add(userId);
                                }
                            }
                        }
                    } catch (Exception ex) {
                        LOG.error(ex, "While parsing user groups!");
                    }
                }
            }
        }

        return userIds;
    }

    private void checkAzureErrors(final JsonNode node, final Response response) {
        if (node.has(ODATA_ERROR_ID)) {
            AzureError.sendError("get object from Azure!", response);
        }
    }

    public static List<Map<String, String>> getMetadata(final String type) {
        return getXMLObjectFromAzureAD(type);
    }

    private static List<Map<String, String>> getXMLObjectFromAzureAD(final String type) {
        List<Map<String, String>> result = new ArrayList<>();

        // e.g. 
        // https://graph.windows.net/[DOMAIN_NAME].onmicrosoft.com/$metadata#directoryObjects/Microsoft.DirectoryServices.User
        WebClient webClient = WebClient
                .create(AzureConnectorConfiguration.DEFAULT_RESOURCE_URI)
                .path("$metadata");

        try {
            HttpURLConnection connection =
                    (HttpURLConnection) new URL(webClient.getCurrentURI().toString()).openConnection();
            connection.setRequestProperty(ACCEPT_HEADER,
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            connection.setRequestProperty("Accept-Encoding", "gzip, deflate, br");
            connection.setRequestMethod("GET");
            InputStream xml = connection.getInputStream();
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

    private String encodeURL(final String parameters) {
        return parameters.replace(" ", "%20");
    }

    public String getDomain() {
        return domain;
    }

    public String getAuthority() {
        return authority;
    }

    public String getClientId() {
        return clientId;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getResourceURI() {
        return resourceURI;
    }

    public String getPagedResultsSkipToken() {
        return pagedResultsSkipToken;
    }

}
