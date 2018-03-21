/**
 * Copyright (C) 2018 ConnId (connid-dev@googlegroups.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.connid.bundles.azure.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.ws.rs.core.Response;
import net.tirasa.connid.bundles.azure.dto.AvailableExtensionProperties;
import net.tirasa.connid.bundles.azure.dto.AzureError;
import net.tirasa.connid.bundles.azure.dto.AzureObject;
import net.tirasa.connid.bundles.azure.dto.AzurePagedObject;
import net.tirasa.connid.bundles.azure.dto.Group;
import net.tirasa.connid.bundles.azure.dto.License;
import net.tirasa.connid.bundles.azure.dto.MemberOf;
import net.tirasa.connid.bundles.azure.dto.PagedGroups;
import net.tirasa.connid.bundles.azure.dto.PagedUsers;
import net.tirasa.connid.bundles.azure.dto.PasswordProfile;
import net.tirasa.connid.bundles.azure.dto.User;
import net.tirasa.connid.bundles.azure.utils.AzureAttributes;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.cxf.jaxrs.client.WebClient;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;

public class AzureRestAPI {

    private static final Log LOG = Log.getLog(AzureRestAPI.class);

    private final AzureService azureService;

    public AzureRestAPI(final AzureService azureService) {
        this.azureService = azureService;
    }

    /**
     *
     * @return List of Users
     */
    public List<User> getAllUsers() {
        WebClient webClient = azureService.getWebclient("users", null);
        return doGetAllUsers(webClient);
    }

    /**
     *
     * @param pageSize
     * @return paged list of Users
     */
    public PagedUsers getAllUsers(final int pageSize) {
        WebClient webClient = azureService.getWebclient("users",
                "$top="
                + String.valueOf(pageSize));

        return PagedUsers.class.cast(getAllPagedObjects("users", webClient, null));
    }

    /**
     *
     * @param pageSize
     * @param skipToken
     * @param backward
     * @return paged list of Users
     */
    public PagedUsers getAllUsersNextPage(final int pageSize, final String skipToken, final Boolean backward) {
        WebClient webClient = azureService.getWebclient("users",
                "$top="
                + String.valueOf(pageSize)
                + (StringUtil.isNotBlank(skipToken)
                ? ("&" + AzureService.SKIP_TOKEN_ID + skipToken) : "")
                + ((backward != null && backward) ? "previous-page=true" : ""));

        return PagedUsers.class.cast(getAllPagedObjects("users", webClient, skipToken));
    }

    /**
     *
     * @param userId
     * @return User
     */
    public User getUser(final String userId) {
        WebClient webClient = azureService.getWebclient("users/" + userId, null);
        return User.class.cast(doGetObject("users", webClient));
    }

    /**
     *
     * @param username
     * @return List of Users
     */
    public List<User> getUsersByName(final String username) {
        WebClient webClient = azureService.getWebclient("users",
                "$filter="
                + AzureAttributes.USER_DISPLAY_NAME
                + " eq '"
                + username
                + "' or "
                + AzureAttributes.USER_MAIL_NICKNAME
                + " eq '"
                + username
                + "'");
        List<User> users = null;
        try {
            users = Arrays.asList(AzureUtils.MAPPER.readValue(
                    azureService.doGetFromAzure(webClient).toString(), User[].class));
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While converting from JSON to Groups", ex);
        }
        return users;
    }

    /**
     *
     * @param groupId
     * @return List of Users
     */
    public List<User> getAllMembersOfGroup(final String groupId) {
        WebClient webClient = azureService.getWebclient("groups/" + groupId + "/members", null);
        List<User> users = null;
        try {
            users = Arrays.asList(AzureUtils.MAPPER.readValue(
                    azureService.doGetFromAzure(webClient).toString(), User[].class));
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While converting from JSON to Users", ex);
        }
        return users;
    }

    /**
     *
     * @param userId
     * @param groupId
     */
    public void addUserToGroup(final String userId, final String groupId) {
        WebClient webClient = azureService.getWebclient("groups/" + groupId + "/$links/members", null);

        WebClient webClientUser = azureService.getWebclient("directoryObjects/" + userId, null);
        ObjectNode json = AzureUtils.MAPPER.createObjectNode();
        json.set("url", json.textNode(webClientUser.getCurrentURI().toString()));

        try {
            webClient.post(AzureUtils.MAPPER.writeValueAsString(json));
        } catch (IOException ex) {
            AzureUtils.handleGeneralError("While adding User to Group", ex);
        }
    }

    /**
     *
     * @param userId
     * @param groupId
     */
    public void deleteUserFromGroup(final String userId, final String groupId) {
        WebClient webClient = azureService.getWebclient("groups/" + groupId + "/$links/members/" + userId, null);
        Response response = webClient.delete();
        if (response.getStatus() != 204) {
            throw new NoSuchEntityException(userId);
        }
    }

    /**
     *
     * @return List of Groups
     */
    public List<Group> getAllGroups() {
        WebClient webClient = azureService.getWebclient("groups", null);
        return doGetAllGroups(webClient);
    }

    /**
     *
     * @param pageSize
     * @return paged list of Groups
     */
    public PagedGroups getAllGroups(final int pageSize) {
        WebClient webClient = azureService.getWebclient("groups",
                "$top="
                + String.valueOf(pageSize));

        return PagedGroups.class.cast(getAllPagedObjects("groups", webClient, null));
    }

    /**
     *
     * @param pageSize
     * @param skipToken
     * @param backward
     * @return paged list of Groups
     */
    public PagedGroups getAllGroupsNextPage(final int pageSize, final String skipToken, final Boolean backward) {
        WebClient webClient = azureService.getWebclient("groups",
                "$top="
                + String.valueOf(pageSize)
                + (StringUtil.isNotBlank(skipToken)
                ? ("&" + AzureService.SKIP_TOKEN_ID + skipToken) : "")
                + (backward != null && backward ? "previous-page=true" : ""));

        return PagedGroups.class.cast(getAllPagedObjects("groups", webClient, skipToken));
    }

    /**
     *
     * @param userId
     * @return List of Groups for specified User
     */
    public List<Group> getAllGroupsForUser(final String userId) {
        WebClient webClient = azureService.getWebclient("users/" + userId + "/$links/memberOf", null);

        List<Group> groups = new ArrayList<>();
        try {
            JsonNode json = azureService.doGetFromAzure(webClient);
            List<String> groupIds = azureService.extractUsersFromGroupMemberships(json);
            for (String groupId : groupIds) {
                Group group = getGroup(groupId);
                if (group != null) {
                    groups.add(group);
                }
            }
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While getting groups for User " + userId, ex);
        }

        return groups;
    }

    /**
     *
     * @param groupId
     * @return Group
     */
    public Group getGroup(final String groupId) {
        WebClient webClient = azureService.getWebclient("groups/" + groupId, null);
        return Group.class.cast(doGetObject("groups", webClient));
    }

    /**
     *
     * @param groupName
     * @return
     */
    public List<Group> getGroupsByName(final String groupName) {
        WebClient webClient = azureService.getWebclient("groups/",
                "$filter="
                + AzureAttributes.GROUP_DISPLAY_NAME
                + " eq '"
                + groupName
                + "'");

        List<Group> groups = null;
        try {
            groups = Arrays.asList(AzureUtils.MAPPER.readValue(
                    azureService.doGetFromAzure(webClient).toString(), Group[].class));
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While converting from JSON to Groups", ex);
        }
        return groups;
    }

    /**
     *
     * @param groupnamePart
     * @return List of Groups
     */
    public List<Group> getGroupsStartsWith(final String groupnamePart) {
        WebClient webClient = azureService.getWebclient("groups/",
                "$filter=startswith(displayName,'" + groupnamePart + "')");

        List<Group> groups = null;
        try {
            groups = Arrays.asList(AzureUtils.MAPPER.readValue(
                    azureService.doGetFromAzure(webClient).toString(), Group[].class));
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While converting from JSON to Groups", ex);
        }
        return groups;
    }

    /**
     *
     * @param attribute
     * @return List of Groups
     */
    public List<Group> getGroupsOrderdByAsc(final String attribute) {
        String attributeToUse = attribute;
        if (StringUtil.isBlank(attributeToUse)) {
            attributeToUse = "displayName";
        }
        WebClient webClient = azureService.getWebclient("groups/",
                "$orderby=" + attributeToUse);

        List<Group> groups = null;
        try {
            groups = Arrays.asList(AzureUtils.MAPPER.readValue(
                    azureService.doGetFromAzure(webClient).toString(), Group[].class));
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While converting from JSON to Users", ex);
        }
        return groups;
    }

    /**
     *
     * @param user
     * @return User
     */
    public User createUser(final User user) {
        return User.class.cast(doCreate(user));
    }

    /**
     *
     * @param group
     * @return Group
     */
    public Group createGroup(final Group group) {
        return Group.class.cast(doCreate(group));
    }

    /**
     *
     * @param user
     * @return User
     */
    public User updateUser(final User user) {
        return User.class.cast(doUpdate(user));
    }

    /**
     *
     * @param group
     * @return Group
     */
    public Group updateGroup(final Group group) {
        return Group.class.cast(doUpdate(group));
    }

    /**
     *
     * @param userId
     */
    public void deleteUser(final String userId) {
        WebClient webClient = azureService.getWebclient("users/" + userId, null);
        if (webClient.delete().getStatus() != 204) {
            throw new NoSuchEntityException(userId);
        }
    }

    /**
     *
     * @param groupId
     */
    public void deleteGroup(final String groupId) {
        WebClient webClient = azureService.getWebclient("groups/" + groupId, null);
        if (webClient.delete().getStatus() != 204) {
            throw new NoSuchEntityException(groupId);
        }
    }

    /**
     * Added from 20-02-2018
     *
     * @param userId
     * @param isSyncedFromOnPremises
     * @return all or a filtered list of the extension properties that have been registered in a directory
     */
    public AvailableExtensionProperties getAvailableExtensionProperties(final String userId,
            final boolean isSyncedFromOnPremises) {
        WebClient webClient = azureService.getWebclient("getAvailableExtensionProperties", null);

        AvailableExtensionProperties availableExtensionProperties = null;
        try {
            ObjectNode body = AzureUtils.MAPPER.createObjectNode();
            body.set("isSyncedFromOnPremises", body.booleanNode(isSyncedFromOnPremises));

            Response response = webClient.post(AzureUtils.MAPPER.writeValueAsString(body));
            String responseAsString = response.readEntity(String.class);
            if (response.getStatus() != 200) {
                AzureError.sendError("get available extension properties for User " + userId, response);
            }
            availableExtensionProperties =
                    AzureUtils.MAPPER.readValue(responseAsString, AvailableExtensionProperties.class);
        } catch (IOException ex) {
            AzureUtils.handleGeneralError("While getting available extension properties ", ex);
        }

        return availableExtensionProperties;
    }

    /**
     * Added from 20-02-2018
     *
     * @return the subscriptions available for the tenant of the signed-in user
     */
    public List<String> getCurrentTenantSubscriptions() {
        WebClient webClient = azureService.getWebclient("subscribedSkus", null);

        List<String> result = new ArrayList<>();
        try {
            JsonNode responseObj = azureService.doGetFromAzure(webClient);
            if (responseObj != null && responseObj.isArray()) {
                for (JsonNode skuId : responseObj.findValues("skuId")) {
                    result.add(skuId.textValue());
                }
            }
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While getting current tenante subscriptions", ex);
        }
        return result;
    }

    /**
     * Added from 20-02-2018
     *
     * @param userId
     * @param assignedLicense
     */
    public void assignLicense(final String userId, final License assignedLicense) {
        WebClient webClient = azureService.getWebclient("users/" + userId + "/assignLicense", null);

        Response response;
        try {
            response = webClient.post(AzureUtils.MAPPER.writeValueAsString(assignedLicense));
            if (response.getStatus() != 200) {
                AzureError.sendError("assign license to User " + userId, response);
            }
        } catch (IOException ex) {
            AzureUtils.handleGeneralError("While assigning license", ex);
        }
    }

    /**
     * Added from 20-02-2018
     *
     * @param memberId
     * @param groupId
     * @return whether a specified user, group, contact, or service principal is a member of a specified group
     */
    public Boolean isMemberOf(final String memberId, final String groupId) {
        WebClient webClient = azureService.getWebclient("isMemberOf", null);

        Boolean result = null;
        try {
            MemberOf memberOf = new MemberOf();
            memberOf.setMemberId(memberId);
            memberOf.setGroupId(groupId);

            Response response = webClient.post(AzureUtils.MAPPER.writeValueAsString(memberOf));
            String responseAsString = response.readEntity(String.class);
            if (response.getStatus() != 200) {
                AzureError.sendError("check whether member " + memberId + " is member of " + groupId, response);
            }
            result = AzureUtils.MAPPER.readTree(responseAsString).get("value").asBoolean();
        } catch (IOException ex) {
            AzureUtils.handleGeneralError("While checking membership", ex);
        }

        return result;
    }

    /**
     * Added from 20-02-2018
     *
     * @param resourceCollection
     * @param resourceId
     * @param securityEnabledOnly
     * @return called on a user, contact, group, or service principal to get the
     * groups that it is a member of
     */
    public List<String> getMemberGroups(final String resourceCollection, final String resourceId,
            final boolean securityEnabledOnly) {
        WebClient webClient =
                azureService.getWebclient(resourceCollection + "/" + resourceId + "/getMemberGroups", null);

        return doGetMembers(webClient, resourceId, securityEnabledOnly);
    }

    /**
     * Added from 20-02-2018
     *
     * @param resourceCollection
     * @param resourceId
     * @param securityEnabledOnly
     * @return called on a user, contact, group, or service principal to get the
     * groups and directory roles that it is a member of
     */
    public List<String> getMemberObjects(final String resourceCollection, final String resourceId,
            final boolean securityEnabledOnly) {
        WebClient webClient =
                azureService.getWebclient(resourceCollection + "/" + resourceId + "/getMemberObjects", null);

        return doGetMembers(webClient, resourceId, securityEnabledOnly);
    }

    private List<String> doGetMembers(final WebClient webClient, final String resourceId,
            final boolean securityEnabledOnly) {
        List<String> result = new ArrayList<>();
        try {
            ObjectNode body = AzureUtils.MAPPER.createObjectNode();
            body.set("securityEnabledOnly", body.booleanNode(securityEnabledOnly));

            Response response = webClient.post(AzureUtils.MAPPER.writeValueAsString(body));
            String responseAsString = response.readEntity(String.class);
            if (response.getStatus() != 200) {
                AzureError.sendError("get members groups for resource " + resourceId, response);
            }
            JsonNode responseObj = AzureUtils.MAPPER.readTree(responseAsString);
            if (responseObj != null && responseObj.isArray()) {
                for (JsonNode value : responseObj.get("value")) {
                    result.add(value.textValue());
                }
            }
        } catch (IOException ex) {
            AzureUtils.handleGeneralError("While getting groups members", ex);
        }

        return result;
    }

    private AzureObject doCreate(final AzureObject obj) {
        WebClient webClient = azureService.getWebclient(
                (obj instanceof Group ? "groups" : "users"), null);
        AzureObject body = obj;

        if (body instanceof User) {
            User user = User.class.cast(body);

            // handle other required attributes
            user.setObjectType("User");
            if (user.getAccountEnabled() == null) {
                user.setAccountEnabled(true);
            }

            checkUserValid(user);

            if (StringUtil.isBlank(user.getUserPrincipalName())) {
                // I'll do this here because it can't be dont in Azure PropagationActions, because REST connector
                // does not have Azure "domain" info in connector configurations list 
                // (as it would do a real full Azure Connector) 
                user.setUserPrincipalName(user.getMailNickname() + "@" + azureService.getDomain());
            }

            // handle passwordProfile object
            PasswordProfile passwordProfile = new PasswordProfile();
            passwordProfile.setPassword(user.getPassword());
            passwordProfile.setEnforceChangePasswordPolicy(false); // check
            passwordProfile.setForceChangePasswordNextLogin(false); // check
            user.setPasswordProfile(passwordProfile);
        } else {
            Group group = Group.class.cast(body);

            group.setObjectType("Group");
            group.setMailEnabled(false); // If 'true' Azure will throw 400 error
            group.setSecurityEnabled(true); // When using Graph API, we can only create pure security groups

            // handle other required attributes
            checkGroupValid(group);
        }

        Response response;
        try {
            response = webClient.post(AzureUtils.MAPPER.writeValueAsString(body));
            // it should return "objectId"
            if (response == null) {
                AzureUtils.handleGeneralError("While creating User - no response");
            } else {
                String value = obj instanceof Group ? AzureAttributes.GROUP_ID : AzureAttributes.USER_ID;
                String responseAsString = response.readEntity(String.class);
                JsonNode responseObj = AzureUtils.MAPPER.readTree(responseAsString);
                if (responseObj.hasNonNull(value)) {
                    body.setObjectId(responseObj.get(value).asText());
                } else {
                    AzureUtils.handleGeneralError(
                            "While getting " + value + " value for created User - Response : " + responseAsString);
                }
            }
        } catch (IOException ex) {
            AzureUtils.handleGeneralError("While creating User", ex);
        }

        return body;
    }

    private AzureObject doUpdate(final AzureObject obj) {
        WebClient webClient;
        AzureObject updated = obj;

        if (updated instanceof User) {
            User updatedUser = User.class.cast(updated);
            webClient = azureService.getWebclient("users/"
                    + (StringUtils.isBlank(updatedUser.getUserPrincipalName())
                    ? updatedUser.getObjectId()
                    : updatedUser.getUserPrincipalName()), null);

            // handle PasswordProfile object - password update
            if ((updatedUser.getPassword() != null
                    && StringUtil.isNotBlank(AzureUtils.getPasswordValue(updatedUser.getPassword())))) {
                PasswordProfile passwordProfile = new PasswordProfile();
                passwordProfile.setPassword(updatedUser.getPassword());
                passwordProfile.setForceChangePasswordNextLogin(false); // important for password updating
                updatedUser.setPasswordProfile(passwordProfile);
            }

            updated = updatedUser;
        } else {
            webClient = azureService.getWebclient("groups/"
                    + obj.getObjectId(), null);
        }

        try {
            WebClient.getConfig(webClient).getRequestContext().put("use.async.http.conduit", true);
            webClient.invoke("PATCH", AzureUtils.MAPPER.writeValueAsString(updated));
        } catch (JsonProcessingException ex) {
            AzureUtils.handleGeneralError("While updating User", ex);
        }

        return obj;
    }

    private List<User> doGetAllUsers(final WebClient webClient) {
        List<User> users = null;
        try {
            users = Arrays.asList(AzureUtils.MAPPER.readValue(
                    azureService.doGetFromAzure(webClient).toString(), User[].class));
        } catch (IOException ex) {
            AzureUtils.handleGeneralError("While converting from JSON to Users", ex);
        }
        return users;
    }

    private List<Group> doGetAllGroups(final WebClient webClient) {
        List<Group> groups = null;
        try {
            groups = Arrays.asList(AzureUtils.MAPPER.readValue(
                    azureService.doGetFromAzure(webClient).toString(), Group[].class));
        } catch (IOException ex) {
            AzureUtils.handleGeneralError("While converting from JSON to Groups", ex);
        }
        return groups;
    }

    private AzurePagedObject getAllPagedObjects(final String type, final WebClient webClient,
            final String skipToken) {
        AzurePagedObject pagedObj = null;
        if (type.equals("users")) {
            PagedUsers pagedUsers = new PagedUsers();
            pagedUsers.setUsers(doGetAllUsers(webClient));
            pagedUsers.setSkipToken(
                    StringUtil.isNotBlank(skipToken) ? skipToken : azureService.getPagedResultsSkipToken());
            pagedObj = pagedUsers;
        } else if (type.equals("groups")) {
            PagedGroups pagedGroups = new PagedGroups();
            pagedGroups.setGroups(doGetAllGroups(webClient));
            pagedGroups.setSkipToken(
                    StringUtil.isNotBlank(skipToken) ? skipToken : azureService.getPagedResultsSkipToken());
            pagedObj = pagedGroups;
        }
        return pagedObj;
    }

    private AzureObject doGetObject(final String type, final WebClient webClient) {
        AzureObject obj = null;
        if (type.equals("users")) {
            try {
                obj = AzureUtils.MAPPER.readValue(
                        azureService.doGetFromAzure(webClient).toString(), User.class);
            } catch (IOException ex) {
                AzureUtils.handleGeneralError("While converting from JSON to User", ex);
            }
        } else if (type.equals("groups")) {
            try {
                obj = AzureUtils.MAPPER.readValue(
                        azureService.doGetFromAzure(webClient).toString(), Group.class);
            } catch (IOException ex) {
                AzureUtils.handleGeneralError("While converting from JSON to Group", ex);
            }
        }
        return obj;
    }

    private void checkUserValid(final User user) {
        if (user.getAccountEnabled() == null) {
            AzureUtils.handleGeneralError("User 'accountEnabled' value is required");
        } else if (StringUtil.isBlank(user.getObjectType())) {
            AzureUtils.handleGeneralError("User 'objectType' value is required");
        } else if (StringUtil.isBlank(user.getDisplayName())) {
            AzureUtils.handleGeneralError("User 'displayName' value is required");
        } else if (StringUtil.isBlank(user.getMailNickname())) {
            AzureUtils.handleGeneralError("User 'mainNickname' value is required");
        } else if (user.getPassword() == null
                || StringUtil.isBlank(AzureUtils.getPasswordValue(user.getPassword()))) {
            AzureUtils.handleGeneralError("User 'password' value is required");
        }
    }

    private void checkGroupValid(final Group group) {
        if (StringUtil.isBlank(group.getDisplayName())) {
            AzureUtils.handleGeneralError("Group 'displayName' value is required");
        } else if (group.getMailEnabled() == null) {
            AzureUtils.handleGeneralError("Group 'mailEnabled' value is required");
        } else if (StringUtil.isBlank(group.getMailNickname())) {
            AzureUtils.handleGeneralError("Group 'mailNickname' value is required");
        } else if (group.getSecurityEnabled() == null) {
            AzureUtils.handleGeneralError("Group 'securityEnabled' value is required");
        }
    }
}
