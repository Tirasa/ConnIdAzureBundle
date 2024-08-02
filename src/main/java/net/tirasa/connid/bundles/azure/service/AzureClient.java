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

import com.microsoft.graph.http.GraphServiceException;
import com.microsoft.graph.models.DirectoryObject;
import com.microsoft.graph.models.DirectoryObjectGetMemberGroupsParameterSet;
import com.microsoft.graph.models.DirectoryObjectGetMemberObjectsParameterSet;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.models.SubscribedSku;
import com.microsoft.graph.models.User;
import com.microsoft.graph.models.UserAssignLicenseParameterSet;
import com.microsoft.graph.options.HeaderOption;
import com.microsoft.graph.options.Option;
import com.microsoft.graph.options.QueryOption;
import com.microsoft.graph.requests.DirectoryObjectCollectionWithReferencesPage;
import com.microsoft.graph.requests.GraphServiceClient;
import com.microsoft.graph.requests.GroupCollectionPage;
import com.microsoft.graph.requests.SubscribedSkuCollectionPage;
import com.microsoft.graph.requests.UserCollectionPage;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import net.tirasa.connid.bundles.azure.AzureConnectorConfiguration;
import net.tirasa.connid.bundles.azure.utils.AzureAttributes;
import net.tirasa.connid.bundles.azure.utils.AzureFilter;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
import org.identityconnectors.common.logging.Log;

public class AzureClient extends AzureService {

    private static final Log LOG = Log.getLog(AzureClient.class);

    public AzureClient(final AzureConnectorConfiguration config) {
        super(config);
    }

    public AzureClient getAuthenticated() {
        checkAuth();

        return this;
    }

    /**
     *
     * @return List of Users
     */
    public List<User> getAllUsers() {
        LOG.ok("Get all users");
        GraphServiceClient graphClient = getGraphServiceClient();
        UserCollectionPage userCollectionPage = graphClient.users().buildRequest().
                select(String.join(",", config.getUserAttributesToGet())).
                orderBy(AzureAttributes.USER_DISPLAY_NAME).get();
        List<User> users = new ArrayList<>();
        if (userCollectionPage != null) {
            users = userCollectionPage.getCurrentPage();
        }
        return users;
    }

    /**
     *
     * @param pageSize
     * @return paged list of Users
     */
    public List<User> getAllUsers(final int pageSize) {
        LOG.ok("Get all users with page size {0}", pageSize);
        GraphServiceClient graphClient = getGraphServiceClient();
        UserCollectionPage userCollectionPage = graphClient.users().buildRequest().
                select(String.join(",", config.getUserAttributesToGet())).
                top(pageSize).orderBy(AzureAttributes.USER_DISPLAY_NAME).get();
        List<User> users = new ArrayList<>();
        if (userCollectionPage != null) {
            users = userCollectionPage.getCurrentPage();
        }
        return users;
    }

    /**
     *
     * @param pageSize
     * @param skipToken
     * @return paged list of Users
     */
    public UserCollectionPage getAllUsersNextPage(final int pageSize, final String skipToken) {
        LOG.ok("Get all users next page with page size {0}", pageSize);
        GraphServiceClient graphClient = getGraphServiceClient();
        return graphClient.users().buildRequest().
                select(String.join(",", config.getUserAttributesToGet())).
                top(pageSize).skipToken(skipToken).orderBy(AzureAttributes.USER_DISPLAY_NAME).get();
    }

    /**
     *
     * @param userId
     * @return User
     */
    public User getUser(final String userId) {
        LOG.ok("Getting user {0}", userId);
        GraphServiceClient graphClient = getGraphServiceClient();
        return graphClient.users(userId).buildRequest().
                select(String.join(",", config.getUserAttributesToGet())).get();
    }

    /**
     *
     * @param filters
     * @return List of Users with specified filters values
     */
    public List<User> getUsersFilteredBy(final AzureFilter filters) {
        GraphServiceClient graphClient = getGraphServiceClient();

        //This request requires the ConsistencyLevel header set to eventual
        //because the request has both the $orderBy and $filter query parameters
        LinkedList<Option> requestOptions = new LinkedList<>();
        requestOptions.add(new HeaderOption("ConsistencyLevel", "eventual"));

        StringBuilder queryFilter = new StringBuilder();
        queryFilter.append(AzureUtils.getFilter(filters));
        LOG.ok("Searching users with filter {0}", queryFilter);
        UserCollectionPage userCollectionPage = graphClient.users().buildRequest(requestOptions).
                select(String.join(",", config.getUserAttributesToGet())).
                filter(queryFilter.toString()).get();

        List<User> users = null;
        if (userCollectionPage != null) {
            users = userCollectionPage.getCurrentPage();
        }
        return users;
    }

    /**
     *
     * @param groupId
     * @return List of Users, members of specified group
     */
    public List<User> getAllMembersOfGroup(final String groupId) {
        LOG.ok("Get all members of group {0}", groupId);
        GraphServiceClient graphClient = getGraphServiceClient();
        DirectoryObjectCollectionWithReferencesPage group = graphClient.groups(groupId).members().buildRequest().get();

        List<User> users = new ArrayList<>();
        if (group != null) {
            group.getCurrentPage().stream().
                    filter(directoryObject -> directoryObject instanceof User).
                    forEach(directoryObject -> users.add((User) directoryObject));
        }
        return users;
    }

    /**
     *
     * @param userId
     * @param groupId
     */
    public void addUserToGroup(final String userId, final String groupId) {
        LOG.ok("Adding user {0} to group {1}", userId, groupId);
        GraphServiceClient graphClient = getGraphServiceClient();
        try {
            graphClient.groups(groupId).members().references()
                    .buildRequest()
                    .post(graphClient.users(userId).buildRequest().get());
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While adding User to Group", ex);
        }
    }

    /**
     *
     * @param userId
     * @param groupId
     */
    public void deleteUserFromGroup(final String userId, final String groupId) {
        LOG.ok("Deleting user {0} from group {1}", userId, groupId);
        GraphServiceClient graphClient = getGraphServiceClient();
        DirectoryObject deletedObject = null;
        try {
            deletedObject = graphClient.groups(groupId).members(userId).reference()
                    .buildRequest()
                    .delete();
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While deleting User from Group", ex);
        }

        if (deletedObject == null) {
            throw new NoSuchEntityException(userId);
        }
    }

    /**
     *
     * @return List of Groups
     */
    public List<Group> getAllGroups() {
        LOG.ok("Get all groups");
        GraphServiceClient graphClient = getGraphServiceClient();
        GroupCollectionPage groupCollectionPage = graphClient.groups()
                .buildRequest()
                .get();
        List<Group> groups = new ArrayList<>();
        if (groupCollectionPage != null) {
            groups = groupCollectionPage.getCurrentPage();
        }
        return groups;
    }

    /**
     *
     * @param pageSize
     * @return paged list of Groups
     */
    public List<Group> getAllGroups(final int pageSize) {
        LOG.ok("Get all groups with page size {0}", pageSize);
        GraphServiceClient graphClient = getGraphServiceClient();
        GroupCollectionPage groupCollectionPage = graphClient.groups().buildRequest().
                top(pageSize).orderBy(AzureAttributes.GROUP_DISPLAY_NAME).get();
        List<Group> groups = new ArrayList<>();
        if (groupCollectionPage != null) {
            groups = groupCollectionPage.getCurrentPage();
        }
        return groups;
    }

    /**
     *
     * @param pageSize
     * @param skipToken
     * @return paged list of Groups
     */
    public GroupCollectionPage getAllGroupsNextPage(final int pageSize, final String skipToken) {
        LOG.ok("Get all groups next page with page size {0}", pageSize);
        GraphServiceClient graphClient = getGraphServiceClient();
        return graphClient.groups().buildRequest().
                top(pageSize).skipToken(skipToken).orderBy(AzureAttributes.GROUP_DISPLAY_NAME).get();
    }

    /**
     *
     * @param userId
     * @return List of Groups for specified User
     */
    public List<Group> getAllGroupsForUser(final String userId) {
        LOG.ok("Get all groups user {0} is member", userId);
        GraphServiceClient graphClient = getGraphServiceClient();
        List<Group> groups = new ArrayList<>();
        try {
            graphClient.users(userId).memberOf().buildRequest().get().getCurrentPage().stream().
                    filter(directoryObject -> directoryObject instanceof Group).
                    forEach(directoryObject -> groups.add((Group) directoryObject));
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
        LOG.ok("Getting group {0}", groupId);
        GraphServiceClient graphClient = getGraphServiceClient();
        return graphClient.groups(groupId).buildRequest().
                select(String.join(",", config.getGroupAttributesToGet())).get();
    }

    /**
     *
     * @param filters
     * @return List of Groups with specified filters values
     */
    public List<Group> getGroupsFilteredBy(final AzureFilter filters) {
        GraphServiceClient graphClient = getGraphServiceClient();

        //This request requires the ConsistencyLevel header set to eventual
        //because the request has both the $orderBy and $filter query parameters
        LinkedList<Option> requestOptions = new LinkedList<>();
        requestOptions.add(new HeaderOption("ConsistencyLevel", "eventual"));

        StringBuilder queryFilter = new StringBuilder();
        queryFilter.append(AzureUtils.getFilter(filters));
        LOG.ok("Searching groups with filter {0}", queryFilter);
        GroupCollectionPage groupCollectionPage = graphClient.groups().buildRequest(requestOptions).
                select(String.join(",", config.getGroupAttributesToGet())).
                filter(queryFilter.toString()).get();

        List<Group> groups = null;
        if (groupCollectionPage != null) {
            groups = groupCollectionPage.getCurrentPage();
        }
        return groups;
    }

    /**
     *
     * @param id
     * @return Deleted DirectoryObject if exists, null otherwise
     */
    public DirectoryObject getDeletedDirectoryObject(final String id) {
        LOG.ok("Get deleted directory object {0} if exists", id);
        GraphServiceClient graphClient = getGraphServiceClient();
        return graphClient.directory().deletedItems(id).buildRequest().get();
    }

    /**
     *
     * @param user
     * @return created User
     */
    public User createUser(final User user) {
        GraphServiceClient graphClient = getGraphServiceClient();
        return graphClient.users().buildRequest().post(user);
    }

    /**
     *
     * @param group
     * @return created Group
     */
    public Group createGroup(final Group group) {
        GraphServiceClient graphClient = getGraphServiceClient();
        return graphClient.groups().buildRequest().post(group);
    }

    /**
     *
     * @param user
     * @return updated User
     */
    public User updateUser(final User user) {
        GraphServiceClient graphClient = getGraphServiceClient();
        graphClient.users(user.id).buildRequest().patch(user);
        return getUser(user.id);
    }

    /**
     *
     * @param group
     * @return updated Group
     */
    public Group updateGroup(final Group group) {
        GraphServiceClient graphClient = getGraphServiceClient();
        return graphClient.groups(group.id).buildRequest().patch(group);
    }

    /**
     *
     * @param userId
     */
    public void deleteUser(final String userId) {
        GraphServiceClient graphClient = getGraphServiceClient();
        graphClient.users(userId).buildRequest().delete();
    }

    /**
     *
     * @param groupId
     */
    public void deleteGroup(final String groupId) {
        GraphServiceClient graphClient = getGraphServiceClient();
        graphClient.groups(groupId).buildRequest().delete();
    }

    /**
     *
     * @param id
     * @return restored DirectoryObject
     */
    public DirectoryObject restoreDirectoryObject(final String id) {
        GraphServiceClient graphClient = getGraphServiceClient();
        return graphClient.directory().deletedItems(id).restore().buildRequest().post();
    }

    /**
     * Added from 20-02-2018
     *
     * @return the existing subscriptions for the current tenant
     */
    public List<SubscribedSku> getCurrentTenantSubscriptions() {
        LOG.ok("Get all subscriptions");
        GraphServiceClient graphClient = getGraphServiceClient();

        SubscribedSkuCollectionPage subscribedSkuCollectionPage = graphClient.subscribedSkus().buildRequest().get();
        List<SubscribedSku> results = null;
        if (subscribedSkuCollectionPage != null) {
            results = subscribedSkuCollectionPage.getCurrentPage();
        }

        return results;
    }

    /**
     * Added from 13-04-2018
     *
     * @param onlyEnabled
     * @return the existing skuIds for the current tenant, only those with "Enabled" status if onlyEnabled
     */
    public List<String> getCurrentTenantSkuIds(final boolean onlyEnabled) {
        LOG.ok("Get all enabled subscriptions");
        List<String> result = new ArrayList<>();

        List<SubscribedSku> subscriptions = getCurrentTenantSubscriptions();
        try {
            for (SubscribedSku subscription : subscriptions) {
                if (onlyEnabled && subscription.capabilityStatus.equalsIgnoreCase("enabled")) {
                    result.add(subscription.skuId.toString());
                } else if (!onlyEnabled) {
                    result.add(subscription.skuId.toString());
                }
            }
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While getting current tenant available licenses", ex);
        }

        return result;
    }

    /**
     * Added from 20-02-2018
     *
     * @param userId
     * @param assignedLicense
     */
    public void assignLicense(final String userId, final UserAssignLicenseParameterSet assignedLicense) {
        LOG.ok("Assigning licenses to user {0}", userId);
        GraphServiceClient graphClient = getGraphServiceClient();
        graphClient.users(userId).assignLicense(assignedLicense).buildRequest().post();
    }

    /**
     * Added from 20-02-2018
     *
     * @param memberId
     * @param groupId
     * @return whether a specified user, group, contact, or service principal is a member of a specified group
     */
    public Boolean isMemberOf(final String memberId, final String groupId) {
        GraphServiceClient graphClient = getGraphServiceClient();

        List<QueryOption> queryOptions = new ArrayList<>();
        queryOptions.add(new QueryOption("$filter", "id eq '" + memberId + "'"));
        try {
            DirectoryObjectCollectionWithReferencesPage result =
                    graphClient.groups(groupId).members().buildRequest(queryOptions).get();

            return result != null;
        } catch (GraphServiceException ex) {
            return false;
        }
    }

    /**
     * Added from 20-02-2018
     *
     * @param resourceId
     * @param securityEnabledOnly
     * @return called on a user, contact, group, or service principal to get the
     * groups that it is a member of
     */
    public List<String> getMemberGroups(final String resourceId, final boolean securityEnabledOnly) {
        GraphServiceClient graphClient = getGraphServiceClient();
        DirectoryObjectGetMemberGroupsParameterSet securityEnabled = new DirectoryObjectGetMemberGroupsParameterSet();
        securityEnabled.securityEnabledOnly = securityEnabledOnly;

        return graphClient.directoryObjects(resourceId).getMemberGroups(securityEnabled).
                buildRequest().post().getCurrentPage();
    }

    /**
     * Added from 20-02-2018
     *
     * @param resourceId
     * @param securityEnabledOnly
     * @return called on a user, contact, group, or service principal to get the
     * groups and directory roles that it is a member of
     */
    public List<String> getMemberObjects(final String resourceId, final boolean securityEnabledOnly) {
        GraphServiceClient graphClient = getGraphServiceClient();
        DirectoryObjectGetMemberObjectsParameterSet securityEnabled = new DirectoryObjectGetMemberObjectsParameterSet();
        securityEnabled.securityEnabledOnly = securityEnabledOnly;

        return graphClient.directoryObjects(resourceId).getMemberObjects(securityEnabled).
                buildRequest().post().getCurrentPage();
    }
}
