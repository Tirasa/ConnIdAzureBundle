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

import com.microsoft.graph.directoryobjects.item.getmembergroups.GetMemberGroupsPostRequestBody;
import com.microsoft.graph.directoryobjects.item.getmemberobjects.GetMemberObjectsPostRequestBody;
import com.microsoft.graph.models.DirectoryObject;
import com.microsoft.graph.models.DirectoryObjectCollectionResponse;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.models.GroupCollectionResponse;
import com.microsoft.graph.models.ReferenceCreate;
import com.microsoft.graph.models.SubscribedSku;
import com.microsoft.graph.models.SubscribedSkuCollectionResponse;
import com.microsoft.graph.models.User;
import com.microsoft.graph.models.UserCollectionResponse;
import com.microsoft.graph.users.item.assignlicense.AssignLicensePostRequestBody;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
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

        UserCollectionResponse result = getGraphServiceClient().users().get(req -> {
            req.queryParameters.select = config.getUserAttributesToGet();
            req.queryParameters.orderby = new String[] { AzureAttributes.USER_DISPLAY_NAME };
        });

        return Optional.ofNullable(result).map(UserCollectionResponse::getValue).orElse(Collections.emptyList());
    }

    /**
     *
     * @param pageSize
     * @return paged list of Users
     */
    public UserCollectionResponse getAllUsers(final int pageSize) {
        LOG.ok("Get all users with page size {0}", pageSize);

        return getGraphServiceClient().users().get(req -> {
            req.queryParameters.select = config.getUserAttributesToGet();
            req.queryParameters.orderby = new String[] { AzureAttributes.USER_DISPLAY_NAME };
            req.queryParameters.top = pageSize;
        });
    }

    public UserCollectionResponse getAllUsersNextPage(final String odataNextLink) {
        LOG.ok("Get all users next page {0}", odataNextLink);

        return getGraphServiceClient().users().withUrl(odataNextLink).get();
    }

    /**
     *
     * @param userId
     * @return User
     */
    public User getUser(final String userId) {
        LOG.ok("Getting user {0}", userId);

        return getGraphServiceClient().users().byUserId(userId).get(req -> {
            req.queryParameters.select = config.getUserAttributesToGet();
        });
    }

    /**
     *
     * @param filters
     * @return List of Users with specified filters values
     */
    public List<User> getUsersFilteredBy(final AzureFilter filters) {
        String filter = AzureUtils.getFilter(filters);
        LOG.ok("Searching users with filter {0}", filter);

        UserCollectionResponse result = getGraphServiceClient().users().get(req -> {
            req.queryParameters.filter = filter;
            req.queryParameters.select = config.getUserAttributesToGet();
            req.queryParameters.orderby = new String[] { AzureAttributes.USER_DISPLAY_NAME };

            // This request requires the ConsistencyLevel header set to eventual
            // because the request has both the $orderBy and $filter query parameters
            req.headers.add("ConsistencyLevel", "eventual");
        });

        return Optional.ofNullable(result).map(UserCollectionResponse::getValue).orElse(Collections.emptyList());
    }

    /**
     *
     * @param groupId
     * @return List of Users, members of specified group
     */
    public List<User> getAllMembersOfGroup(final String groupId) {
        LOG.ok("Get all members of group {0}", groupId);

        DirectoryObjectCollectionResponse result = getGraphServiceClient().groups().byGroupId(groupId).members().get();

        List<User> users = new ArrayList<>();
        if (result != null) {
            result.getValue().stream().
                    filter(User.class::isInstance).
                    map(User.class::cast).
                    forEach(users::add);
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

        try {
            ReferenceCreate referenceCreate = new ReferenceCreate();
            referenceCreate.setOdataId("https://graph.microsoft.com/v1.0/directoryObjects/" + userId);
            getGraphServiceClient().groups().byGroupId(groupId).members().ref().post(referenceCreate);
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

        try {
            getGraphServiceClient().groups().byGroupId(groupId).
                    members().byDirectoryObjectId(userId).ref().delete();
        } catch (Exception ex) {
            AzureUtils.handleGeneralError("While deleting User from Group", ex);
        }
    }

    /**
     *
     * @return List of Groups
     */
    public List<Group> getAllGroups() {
        LOG.ok("Get all groups");

        GroupCollectionResponse result = getGraphServiceClient().groups().get(req -> {
            req.queryParameters.select = config.getGroupAttributesToGet();
            req.queryParameters.orderby = new String[] { AzureAttributes.GROUP_DISPLAY_NAME };
        });

        return Optional.ofNullable(result).map(GroupCollectionResponse::getValue).orElse(Collections.emptyList());
    }

    /**
     *
     * @param pageSize
     * @return paged list of Groups
     */
    public GroupCollectionResponse getAllGroups(final int pageSize) {
        LOG.ok("Get all groups with page size {0}", pageSize);

        return getGraphServiceClient().groups().get(req -> {
            req.queryParameters.select = config.getGroupAttributesToGet();
            req.queryParameters.orderby = new String[] { AzureAttributes.GROUP_DISPLAY_NAME };
            req.queryParameters.top = pageSize;
        });
    }

    public GroupCollectionResponse getAllGroupsNextPage(final String odataNextLink) {
        LOG.ok("Get all groups next page {0}", odataNextLink);

        return getGraphServiceClient().groups().withUrl(odataNextLink).get();
    }

    /**
     *
     * @param userId
     * @return List of Groups for specified User
     */
    public List<Group> getAllGroupsForUser(final String userId) {
        LOG.ok("Get all groups user {0} is member", userId);

        DirectoryObjectCollectionResponse result = getGraphServiceClient().users().byUserId(userId).memberOf().get();

        List<Group> groups = new ArrayList<>();
        if (result != null) {
            result.getValue().stream().
                    filter(Group.class::isInstance).
                    map(Group.class::cast).
                    forEach(groups::add);
        }
        return groups;
    }

    /**
     *
     * @param groupId
     * @return List of Groups for specified Group
     */
    public List<Group> getAllGroupsForGroup(final String groupId) {
        LOG.ok("Get all groups group {0} is member", groupId);

        DirectoryObjectCollectionResponse result = getGraphServiceClient().groups().byGroupId(groupId).memberOf().get();

        List<Group> groups = new ArrayList<>();
        if (result != null) {
            result.getValue().stream().
                    filter(Group.class::isInstance).
                    map(Group.class::cast).
                    forEach(groups::add);
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

        return getGraphServiceClient().groups().byGroupId(groupId).get(req -> {
            req.queryParameters.select = config.getGroupAttributesToGet();
        });
    }

    /**
     *
     * @param filters
     * @return List of Groups with specified filters values
     */
    public List<Group> getGroupsFilteredBy(final AzureFilter filters) {
        String filter = AzureUtils.getFilter(filters);
        LOG.ok("Searching groups with filter {0}", filter);

        GroupCollectionResponse result = getGraphServiceClient().groups().get(req -> {
            req.queryParameters.filter = filter;
            req.queryParameters.select = config.getGroupAttributesToGet();
            req.queryParameters.orderby = new String[] { AzureAttributes.GROUP_DISPLAY_NAME };

            // This request requires the ConsistencyLevel header set to eventual
            // because the request has both the $orderBy and $filter query parameters
            req.headers.add("ConsistencyLevel", "eventual");
        });

        return Optional.ofNullable(result).map(GroupCollectionResponse::getValue).orElse(Collections.emptyList());
    }

    /**
     *
     * @param id
     * @return Deleted DirectoryObject if exists, null otherwise
     */
    public DirectoryObject getDeletedDirectoryObject(final String id) {
        LOG.ok("Get deleted directory object {0} if exists", id);

        return getGraphServiceClient().directory().deletedItems().byDirectoryObjectId(id).get();
    }

    /**
     *
     * @param user
     * @return created User
     */
    public User createUser(final User user) {
        return getGraphServiceClient().users().post(user);
    }

    /**
     *
     * @param group
     * @return created Group
     */
    public Group createGroup(final Group group) {
        return getGraphServiceClient().groups().post(group);
    }

    /**
     *
     * @param user
     * @return updated User
     */
    public User updateUser(final User user) {
        return getGraphServiceClient().users().byUserId(user.getId()).patch(user);
    }

    /**
     *
     * @param group
     * @return updated Group
     */
    public Group updateGroup(final Group group) {
        return getGraphServiceClient().groups().byGroupId(group.getId()).patch(group);
    }

    /**
     *
     * @param userId
     */
    public void deleteUser(final String userId) {
        getGraphServiceClient().users().byUserId(userId).delete();
    }

    /**
     *
     * @param groupId
     */
    public void deleteGroup(final String groupId) {
        getGraphServiceClient().groups().byGroupId(groupId).delete();
    }

    /**
     *
     * @param id
     * @return restored DirectoryObject
     */
    public DirectoryObject restoreDirectoryObject(final String id) {
        return getGraphServiceClient().directory().deletedItems().byDirectoryObjectId(id).restore().post();
    }

    /**
     * Added from 20-02-2018
     *
     * @return the existing subscriptions for the current tenant
     */
    public List<SubscribedSku> getCurrentTenantSubscriptions() {
        LOG.ok("Get all subscriptions");

        SubscribedSkuCollectionResponse result = getGraphServiceClient().subscribedSkus().get();

        return Optional.ofNullable(result).
                map(SubscribedSkuCollectionResponse::getValue).
                orElse(Collections.emptyList());
    }

    /**
     * Added from 13-04-2018
     *
     * @param onlyEnabled
     * @return the existing skuIds for the current tenant, only those with "Enabled" status if onlyEnabled
     */
    public List<String> getCurrentTenantSkuIds(final boolean onlyEnabled) {
        LOG.ok("Get all enabled subscriptions");

        SubscribedSkuCollectionResponse result = getGraphServiceClient().subscribedSkus().get();

        if (result == null) {
            return Collections.emptyList();
        }

        return result.getValue().stream().
                filter(sku -> !onlyEnabled || sku.getCapabilityStatus().equalsIgnoreCase("enabled")).
                map(SubscribedSku::toString).
                collect(Collectors.toList());
    }

    /**
     * Added from 20-02-2018
     *
     * @param userId
     * @param assignedLicense
     */
    public void assignLicense(final String userId, final AssignLicensePostRequestBody assignedLicense) {
        LOG.ok("Assigning licenses to user {0}", userId);

        getGraphServiceClient().users().byUserId(userId).assignLicense().post(assignedLicense);
    }

    /**
     * Added from 20-02-2018
     *
     * @param memberId
     * @param groupId
     * @return whether a specified user, group, contact, or service principal is a member of a specified group
     */
    public boolean isMemberOf(final String memberId, final String groupId) {
        DirectoryObjectCollectionResponse result = getGraphServiceClient().groups().byGroupId(groupId).
                members().get(req -> {
                    req.queryParameters.filter = "id eq '" + memberId + "'";
                });

        return Optional.ofNullable(result).map(r -> !r.getValue().isEmpty()).orElse(false);
    }

    /**
     * Added from 20-02-2018
     *
     * @param resourceId
     * @param securityEnabledOnly
     * @return called on a user, contact, group, or service principal to get the groups that it is a member of
     */
    public List<String> getMemberGroups(final String resourceId, final boolean securityEnabledOnly) {
        GetMemberGroupsPostRequestBody securityEnabled = new GetMemberGroupsPostRequestBody();
        securityEnabled.setSecurityEnabledOnly(securityEnabledOnly);

        return getGraphServiceClient().directoryObjects().byDirectoryObjectId(resourceId).
                getMemberGroups().post(securityEnabled).getValue();
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
        GetMemberObjectsPostRequestBody securityEnabled = new GetMemberObjectsPostRequestBody();
        securityEnabled.setSecurityEnabledOnly(securityEnabledOnly);

        return getGraphServiceClient().directoryObjects().byDirectoryObjectId(resourceId).
                getMemberObjects().post(securityEnabled).getValue();
    }
}
