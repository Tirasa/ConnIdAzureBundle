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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.microsoft.graph.models.AssignedLicense;
import com.microsoft.graph.models.AssignedPlan;
import com.microsoft.graph.models.DirectoryObject;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.models.PasswordProfile;
import com.microsoft.graph.models.ProvisionedPlan;
import com.microsoft.graph.models.SubscribedSku;
import com.microsoft.graph.models.User;
import com.microsoft.graph.models.UserAssignLicenseParameterSet;
import com.microsoft.graph.requests.GroupCollectionPage;
import com.microsoft.graph.requests.GroupCollectionRequestBuilder;
import com.microsoft.graph.requests.UserCollectionPage;
import com.microsoft.graph.requests.UserCollectionRequestBuilder;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import net.tirasa.connid.bundles.azure.service.AzureClient;
import net.tirasa.connid.bundles.azure.utils.AzureAttributes;
import net.tirasa.connid.bundles.azure.utils.AzureFilter;
import net.tirasa.connid.bundles.azure.utils.AzureFilterOp;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.AttributesAccessor;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.PredefinedAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;

@ConnectorClass(displayNameKey = "AzureConnector.connector.display",
        configurationClass = AzureConnectorConfiguration.class)
public class AzureConnector implements
        Connector, CreateOp, DeleteOp, SchemaOp, SearchOp<AzureFilter>, TestOp, UpdateOp {

    public static final String SKIP_TOKEN_ID = "$skiptoken=";

    private static final Log LOG = Log.getLog(AzureConnector.class);

    private AzureConnectorConfiguration configuration;

    private Schema schema;

    private AzureClient client;

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(final Configuration configuration) {
        LOG.ok("Init");

        this.configuration = (AzureConnectorConfiguration) configuration;
        this.configuration.validate();

        client = new AzureClient(this.configuration);

        LOG.ok("Connector {0} successfully inited", getClass().getName());
    }

    @Override
    public void dispose() {
        LOG.ok("Configuration cleanup");

        configuration = null;
    }

    @Override
    public void test() {
        LOG.ok("connector TEST");

        if (configuration != null) {

            if (client.getAuthenticated() != null) {
                LOG.ok("Test was successful");
            } else {
                AzureUtils.handleGeneralError("Test error. Problems with client service");
            }

        } else {
            LOG.error("Error with establishing connection while testing. "
                    + "No instance of the configuration class");
        }
    }

    @Override
    public Schema schema() {
        LOG.ok("Building SCHEMA definition");

        if (schema == null) {
            schema = AzureAttributes.buildSchema();
        }
        return schema;
    }

    @Override
    public FilterTranslator<AzureFilter> createFilterTranslator(
            final ObjectClass objectClass,
            final OperationOptions options) {

        LOG.ok("check the ObjectClass");
        if (objectClass == null) {
            throw new IllegalArgumentException("Object class not supported");
        }
        LOG.ok("The ObjectClass is ok");
        return new AzureFilterTranslator(objectClass);
    }

    @Override
    public void executeQuery(
            final ObjectClass objectClass,
            final AzureFilter query,
            final ResultsHandler handler,
            final OperationOptions options) {

        LOG.ok("Connector READ");

        Attribute key = null;
        boolean moreFilters = true;
        if (query != null) {
            Attribute filterAttr = query.getAttribute();
            if (filterAttr instanceof Uid) {
                key = filterAttr;
            } else if (ObjectClass.ACCOUNT.equals(objectClass) || ObjectClass.GROUP.equals(objectClass)) {
                key = filterAttr;
            }
            if (key == null && !query.getFilters().isEmpty()) {
                moreFilters = false;
            }
        }

        Set<String> attributesToGet = new HashSet<>();
        if (options.getAttributesToGet() != null) {
            attributesToGet.addAll(Arrays.asList(options.getAttributesToGet()));
        }

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            if (key == null && moreFilters) {
                List<User> users = null;
                int remainingResults = -1;
                int pagesSize = options.getPageSize() != null ? options.getPageSize() : -1;
                String cookie = options.getPagedResultsCookie();

                try {
                    if (pagesSize != -1) {
                        if (StringUtil.isNotBlank(cookie)) {
                            UserCollectionPage request =
                                    client.getAuthenticated().getAllUsersNextPage(pagesSize, cookie);
                            users = request.getCurrentPage();
                            cookie = request.getNextPage() != null ? getSkipToken(request.getNextPage()) : null;
                        } else {
                            users = client.getAuthenticated().getAllUsers(pagesSize);

                            UserCollectionRequestBuilder nextPageRequest =
                                    client.getAuthenticated().getAllUsersNextPage(pagesSize, "").getNextPage();
                            cookie = nextPageRequest != null
                                    && nextPageRequest.buildRequest().get().getNextPage() != null
                                    ? getSkipToken(nextPageRequest) : null;
                        }
                    } else {
                        users = client.getAuthenticated().getAllUsers();
                    }
                } catch (Exception e) {
                    AzureUtils.wrapGeneralError("While getting Users!", e);
                }

                if (users != null) {
                    users.forEach(user -> handler.handle(fromUser(user, attributesToGet)));
                }

                if (handler instanceof SearchResultsHandler) {
                    ((SearchResultsHandler) handler).handleResult(new SearchResult(cookie, remainingResults));
                }
            } else {
                if (AzureFilterOp.EQUALS == query.getFilterOp()
                        && (Uid.NAME.equals(key.getName())
                        || AzureAttributes.USER_ID.equals(key.getName()))) {

                    User result = null;
                    try {
                        result = client.getAuthenticated().getUser(AttributeUtil.getAsStringValue(key));
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError("While getting User : "
                                + key.getName() + " - " + AttributeUtil.getAsStringValue(key), e);
                    }
                    if (result != null) {
                        handler.handle(fromUser(result, attributesToGet));
                    }
                } else {
                    List<User> result = null;
                    try {
                        result = client.getAuthenticated().getUsersFilteredBy(query);
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError("While searching with key : "
                                + key.getName() + " - " + AttributeUtil.getAsStringValue(key), e);
                    }
                    if (result != null) {
                        result.forEach(user -> handler.handle(fromUser(user, attributesToGet)));
                    }
                }
            }

        } else if (ObjectClass.GROUP.equals(objectClass)) {
            if (key == null && moreFilters) {
                List<Group> groups = null;
                int remainingResults = -1;
                int pagesSize = options.getPageSize() != null ? options.getPageSize() : -1;
                String cookie = options.getPagedResultsCookie();

                try {
                    if (pagesSize != -1) {
                        if (StringUtil.isNotBlank(cookie)) {
                            GroupCollectionPage request =
                                    client.getAuthenticated().getAllGroupsNextPage(pagesSize, cookie);
                            groups = request.getCurrentPage();
                            cookie = request.getNextPage() != null ? getGroupSkipToken(request.getNextPage()) : null;
                        } else {
                            groups = client.getAuthenticated().getAllGroups(pagesSize);

                            GroupCollectionRequestBuilder request =
                                    client.getAuthenticated().getAllGroupsNextPage(pagesSize, "").getNextPage();
                            cookie = request.buildRequest().get().getNextPage() != null
                                    ? getGroupSkipToken(request) : null;
                        }
                    } else {
                        groups = client.getAuthenticated().getAllGroups();
                    }
                } catch (Exception e) {
                    AzureUtils.wrapGeneralError("While getting Groups!", e);
                }

                if (groups != null) {
                    groups.forEach(group -> handler.handle(fromGroup(group, attributesToGet)));
                }

                if (handler instanceof SearchResultsHandler) {
                    ((SearchResultsHandler) handler).handleResult(new SearchResult(cookie, remainingResults));
                }

            } else {
                if (AzureFilterOp.EQUALS == query.getFilterOp() && (Uid.NAME.equals(key.getName())
                        || AzureAttributes.GROUP_ID.equals(key.getName()))) {
                    Group result = null;
                    try {
                        result = client.getAuthenticated().getGroup(AttributeUtil.getAsStringValue(key));
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError("While getting Group!", e);
                    }
                    if (result != null) {
                        handler.handle(fromGroup(result, attributesToGet));
                    }
                } else {
                    List<Group> result = null;
                    try {
                        result = client.getAuthenticated().getGroupsFilteredBy(query);
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError("While searching with key : "
                                + key.getName() + " - " + AttributeUtil.getAsStringValue(key), e);
                    }
                    if (result != null) {
                        result.forEach(group -> handler.handle(fromGroup(group, attributesToGet)));
                    }
                }
            }
        } else if (new ObjectClass(AzureAttributes.AZURE_LICENSE_NAME).equals(objectClass)) {
            if (key == null) {
                List<SubscribedSku> subscribedSkus = null;
                try {
                    subscribedSkus = client.getAuthenticated().getCurrentTenantSubscriptions();
                } catch (Exception e) {
                    AzureUtils.wrapGeneralError("While getting subscriptions!", e);
                }

                if (subscribedSkus != null) {
                    for (SubscribedSku subscribedSku : subscribedSkus) {
                        handler.handle(fromLicense(subscribedSku, attributesToGet));
                    }
                }

                if (handler instanceof SearchResultsHandler) {
                    ((SearchResultsHandler) handler).handleResult(new SearchResult(null, -1));
                }
            }
        } else {
            LOG.warn("Search of type " + objectClass.getObjectClassValue() + " is not supported");
            throw new UnsupportedOperationException("Search of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }

    }

    @Override
    public Uid create(
            final ObjectClass objectClass,
            final Set<Attribute> createAttributes,
            final OperationOptions options) {

        LOG.ok("Connector CREATE");

        if (CollectionUtil.isEmpty(createAttributes)) {
            AzureUtils.handleGeneralError("Set of Attributes value is null or empty");
        }

        final AttributesAccessor accessor = new AttributesAccessor(createAttributes);

        String id = accessor.findString(AzureAttributes.USER_ID);
        if (configuration.getRestoreItems() && id != null && client.getDeletedDirectoryObject(id) != null) {
            DirectoryObject directoryObject = client.restoreDirectoryObject(id);
            return new Uid(directoryObject.id);
        } else if (ObjectClass.ACCOUNT.equals(objectClass)) {
            User user = new User();
            User createdUser = new User();
            String username = accessor.findString(AzureAttributes.USER_MAIL_NICKNAME);
            if (username == null) {
                username = accessor.findString(Name.NAME);
            }
            GuardedString password = accessor.getPassword();
            String displayName = accessor.findString(AzureAttributes.USER_DISPLAY_NAME);
            boolean status = accessor.getEnabled(true);
            List<Object> licenses = accessor.findList(AzureAttributes.AZURE_LICENSE_NAME);

            try {
                // handle mandatory attributes (some attributes are handled by Service class)
                user.displayName = displayName;
                user.mailNickname = username;

                PasswordProfile passwordProfile = new PasswordProfile();
                passwordProfile.password = String.valueOf(password);
                user.passwordProfile = passwordProfile;

                user.accountEnabled = status;

                createAttributes.forEach(attr -> doUserSetAttribute(attr.getName(), attr.getValue(), user));

                createdUser = client.getAuthenticated().createUser(user);
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not create User : " + username, e);
            }

            // memberships
            List<Object> groups = accessor.findList(PredefinedAttributes.GROUPS_NAME);
            if (!CollectionUtil.isEmpty(groups)) {
                for (Object group : groups) {
                    try {
                        client.getAuthenticated().addUserToGroup(createdUser.id, group.toString());
                    } catch (Exception e) {
                        LOG.error("Could not add User {0} to Group {1} ", createdUser.id, group, e);
                    }
                }
            }

            // licenses
            if (!CollectionUtil.isEmpty(licenses)) {
                for (Object license : licenses) {
                    // executing an assignment per single license in order to skip errors from invalid licenses
                    try {
                        UserAssignLicenseParameterSet userAssignLicenseParameterSet =
                                new UserAssignLicenseParameterSet();
                        AssignedLicense assignedLicense = new AssignedLicense();
                        assignedLicense.skuId = (UUID.fromString(license.toString()));
                        LinkedList<AssignedLicense> assignedLicenses = new LinkedList<>();
                        assignedLicenses.add(assignedLicense);
                        List<UUID> removedLicenses = new ArrayList<>();
                        userAssignLicenseParameterSet.addLicenses = assignedLicenses;
                        userAssignLicenseParameterSet.removeLicenses = removedLicenses;
                        client.getAuthenticated().assignLicense(createdUser.id, userAssignLicenseParameterSet);
                    } catch (RuntimeException ex) {
                        LOG.error("While assigning license {0} to user {1}", license, createdUser, ex);
                    }
                }
            }

            return new Uid(createdUser.id);

        } else if (ObjectClass.GROUP.equals(objectClass)) {
            String groupName = accessor.findString(AzureAttributes.GROUP_MAIL_NICKNAME);
            if (groupName == null) {
                groupName = accessor.findString(Name.NAME);
            }
            String displayName = accessor.findString(AzureAttributes.GROUP_DISPLAY_NAME);

            Group group = new Group();
            Group createdGroup = new Group();
            try {
                // handle mandatory attributes (some attributes are handled by Service class)
                group.displayName = displayName;
                group.mailNickname = groupName;

                createAttributes.forEach(attribute
                        -> doGroupSetAttribute(attribute.getName(), attribute.getValue(), group));
                createdGroup = client.getAuthenticated().createGroup(group);
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not create Group : " + groupName, e);
            }

            return new Uid(createdGroup.id);

        } else {
            LOG.warn("Create of type " + objectClass.getObjectClassValue() + " is not supported");
            throw new UnsupportedOperationException("Create of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }
    }

    @Override
    public void delete(final ObjectClass objectClass, final Uid uid, final OperationOptions options) {
        LOG.ok("Connector DELETE");

        if (StringUtil.isBlank(uid.getUidValue())) {
            LOG.error("Uid not provided or empty ");
            throw new InvalidAttributeValueException("Uid value not provided or empty");
        }

        if (objectClass == null) {
            LOG.error("Object value not provided ");
            throw new InvalidAttributeValueException("Object value not provided");
        }

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            try {
                for (Group group : client.getAuthenticated().getAllGroupsForUser(uid.getUidValue())) {
                    client.getAuthenticated().deleteUserFromGroup(uid.getUidValue(), group.id);
                }
            } catch (Exception e) {
                LOG.error("Could not delete User {0} from Groups", uid.getUidValue());
            }

            try {
                client.getAuthenticated().deleteUser(uid.getUidValue());
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not delete User " + uid.getUidValue(), e);
            }

        } else if (ObjectClass.GROUP.equals(objectClass)) {
            try {
                client.getAuthenticated().deleteGroup(uid.getUidValue());
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not delete Group " + uid.getUidValue(), e);
            }

        } else {
            LOG.warn("Delete of type " + objectClass.getObjectClassValue() + " is not supported");
            throw new UnsupportedOperationException("Delete of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }
    }

    @Override
    public Uid update(
            final ObjectClass objectClass,
            final Uid uid,
            final Set<Attribute> replaceAttributes,
            final OperationOptions options) {

        LOG.ok("Connector UPDATE");

        if (replaceAttributes == null || replaceAttributes.isEmpty()) {
            AzureUtils.handleGeneralError("Set of Attributes value is null or empty");
        }

        final AttributesAccessor accessor = new AttributesAccessor(replaceAttributes);

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            Uid returnUid = uid;

            String displayName = accessor.findString(AzureAttributes.USER_DISPLAY_NAME);
            Attribute status = accessor.find(AzureAttributes.USER_ACCOUNT_ENABLED);
            List<Object> licenses = accessor.findList(AzureAttributes.AZURE_LICENSE_NAME);

            if (displayName == null) {
                AzureUtils.handleGeneralError("The " + AzureAttributes.USER_DISPLAY_NAME
                        + " property cannot be cleared during updates");
            }

            User user = new User();
            user.id = uid.getUidValue();

            if (status == null
                    || status.getValue() == null
                    || status.getValue().isEmpty()) {
                LOG.warn("{0} attribute value not correct, can't handle User status update",
                        OperationalAttributes.ENABLE_NAME);
            } else {
                user.accountEnabled = Boolean.valueOf(status.getValue().get(0).toString());
            }

            try {
                replaceAttributes.forEach(attr -> doUserSetAttribute(attr.getName(), attr.getValue(), user));

                // password
                GuardedString password = accessor.getPassword();
                if (password != null) {
                    try {
                        if (user.passwordProfile != null) {
                            PasswordProfile passwordProfile = new PasswordProfile();
                            passwordProfile.password = String.valueOf(password);
                            user.passwordProfile = passwordProfile;
                        }
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError(
                                "Could not update password for User " + uid.getUidValue(), e);
                    }
                }

                client.getAuthenticated().updateUser(user);

                returnUid = new Uid(user.id);
            } catch (Exception e) {
                AzureUtils.wrapGeneralError(
                        "Could not update User " + uid.getUidValue() + " from attributes ", e);
            }

            // memberships
            Set<String> ownGroups = new HashSet<>();
            try {
                List<Group> ownGroupsResults =
                        client.getAuthenticated().getAllGroupsForUser(returnUid.getUidValue());
                for (Group group : ownGroupsResults) {
                    ownGroups.add(group.id);
                }
            } catch (Exception ex) {
                LOG.error(ex, "Could not list groups for User {0}", uid.getUidValue());
            }

            List<Object> groups = CollectionUtil.nullAsEmpty(accessor.findList(PredefinedAttributes.GROUPS_NAME));
            for (Object group : groups) {
                if (!ownGroups.contains(group.toString())) {
                    try {
                        client.getAuthenticated().addUserToGroup(returnUid.getUidValue(), group.toString());
                        LOG.ok("User added to Group: {0} after update", group);
                    } catch (Exception e) {
                        LOG.error(e, "Could not add User {0} to Group {1} ", returnUid.getUidValue(), group);
                    }
                }
            }
            for (String group : ownGroups) {
                if (!groups.contains(group)) {
                    try {
                        client.getAuthenticated().deleteUserFromGroup(returnUid.getUidValue(), group);
                        LOG.ok("User removed from group: {0} after update", group);
                    } catch (Exception e) {
                        LOG.error(e, "Could not remove Group {0} from User {1} ", group, returnUid.getUidValue());
                    }
                }
            }

            // licenses
            User updatedUser = client.getAuthenticated().getUser(returnUid.getUidValue());
            if (updatedUser == null) {
                LOG.error("While reading user {0} after update in order to handle licenses update",
                        returnUid.getUidValue());
            } else {
                List<UUID> assignedSkuIds = new ArrayList<>();
                if (updatedUser.assignedLicenses != null) {
                    for (AssignedLicense assignedLicense : updatedUser.assignedLicenses) {
                        assignedSkuIds.add(assignedLicense.skuId);
                    }
                }

                if (CollectionUtil.isEmpty(licenses)) {
                    if (!assignedSkuIds.isEmpty()) {
                        assignedSkuIds.forEach(uuid -> {
                            UserAssignLicenseParameterSet userAssignLicenseParameterSet =
                                    new UserAssignLicenseParameterSet();
                            LinkedList<AssignedLicense> assignedLicenses = new LinkedList<>();
                            List<UUID> removedLicenses = new ArrayList<>();
                            removedLicenses.add(uuid);
                            userAssignLicenseParameterSet.addLicenses = assignedLicenses;
                            userAssignLicenseParameterSet.removeLicenses = removedLicenses;
                            client.getAuthenticated().assignLicense(user.id, userAssignLicenseParameterSet);
                        });
                    }
                } else {
                    List<UUID> toRemove = new ArrayList<>();
                    List<UUID> newLicenses = new ArrayList<>();
                    for (Object license : licenses) {
                        newLicenses.add(UUID.fromString(license.toString()));
                    }
                    for (UUID assignedSkuId : assignedSkuIds) {
                        if (!newLicenses.contains(assignedSkuId)) {
                            toRemove.add(assignedSkuId);
                        }
                    }
                    for (UUID newLicense : newLicenses) {
                        if (!assignedSkuIds.contains(newLicense)) {
                            // executing an assignment per single license in order to skip errors from invalid licenses
                            try {
                                UserAssignLicenseParameterSet userAssignLicenseParameterSet =
                                        new UserAssignLicenseParameterSet();
                                AssignedLicense assignedLicense = new AssignedLicense();
                                assignedLicense.skuId = newLicense;
                                LinkedList<AssignedLicense> assignedLicenses = new LinkedList<>();
                                assignedLicenses.add(assignedLicense);
                                List<UUID> removedLicenses = new ArrayList<>();
                                userAssignLicenseParameterSet.addLicenses = assignedLicenses;
                                userAssignLicenseParameterSet.removeLicenses = removedLicenses;
                                client.getAuthenticated().assignLicense(user.id, userAssignLicenseParameterSet);
                            } catch (RuntimeException ex) {
                                LOG.error(ex, "While assigning license {0} to user {1}", newLicense, user);
                            }
                        }
                    }

                    if (!toRemove.isEmpty()) {
                        try {
                            UserAssignLicenseParameterSet userAssignLicenseParameterSet =
                                    new UserAssignLicenseParameterSet();
                            LinkedList<AssignedLicense> assignedLicenses = new LinkedList<>();
                            userAssignLicenseParameterSet.removeLicenses = toRemove;
                            userAssignLicenseParameterSet.addLicenses = assignedLicenses;
                            client.getAuthenticated().assignLicense(user.id, userAssignLicenseParameterSet);
                        } catch (RuntimeException ex) {
                            LOG.error(ex, "While removing licenses from user {1}", user);
                        }
                    }
                }

            }

            return returnUid;
        } else if (ObjectClass.GROUP.equals(objectClass)) {
            Uid returnUid = uid;

            // group name
            String groupID = accessor.findString(AzureAttributes.GROUP_ID);
            if (groupID == null) {
                groupID = accessor.findString(Name.NAME);
            }
            String mailNickname = accessor.findString(AzureAttributes.GROUP_MAIL_NICKNAME);
            String displayName = accessor.findString(AzureAttributes.GROUP_DISPLAY_NAME);

            Group group = new Group();
            group.id = uid.getUidValue();

            if (!uid.getUidValue().equals(groupID)) {
                LOG.info("Update - uid value different from Group ID");

                group.mailNickname = mailNickname;
                group.displayName = displayName;
            }

            try {
                replaceAttributes.forEach(attr -> doGroupSetAttribute(attr.getName(), attr.getValue(), group));
                client.getAuthenticated().updateGroup(group);

                returnUid = new Uid(group.id);
            } catch (Exception e) {
                AzureUtils.wrapGeneralError(
                        "Could not update Group " + uid.getUidValue() + " from attributes ", e);
            }

            return returnUid;

        } else {
            LOG.warn("Update of type {0} is not supported", objectClass.getObjectClassValue());
            throw new UnsupportedOperationException("Update of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }
    }

    public AzureClient getClient() {
        return client;
    }

    private ConnectorObject fromUser(final User user, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.ACCOUNT);
        builder.setUid(user.id);
        builder.setName(user.userPrincipalName);

        try {
            Set<Attribute> attrs = new HashSet<>();

            Field[] fields = User.class.getDeclaredFields();
            for (Field field : fields) {
                if (field.getAnnotation(JsonIgnore.class) == null) {
                    field.setAccessible(true);
                    if (field.getName().equals(AzureAttributes.USER_PASSWORD_PROFILE) && user.passwordProfile != null) {
                        attrs.add(AttributeBuilder.build(AzureAttributes.USER_PASSWORD_PROFILE,
                                user.passwordProfile.password == null
                                        ? null
                                        : new GuardedString(user.passwordProfile.password.toCharArray())));
                    } else if (field.getName().equals(AzureAttributes.USER_ACCOUNT_ENABLED)
                            && user.accountEnabled != null) {
                        attrs.add(AttributeBuilder.build(AzureAttributes.USER_ACCOUNT_ENABLED, user.accountEnabled));
                    } else {
                        switch (field.getName()) {
                            case "displayName":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.displayName,
                                        field.getName(), field.getType()).build());
                                break;
                            case "id":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.id,
                                        field.getName(), field.getType()).build());
                                break;
                            case "userPrincipalName":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.userPrincipalName,
                                        field.getName(), field.getType()).build());
                                break;
                            case "city":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.city,
                                        field.getName(), field.getType()).build());
                                break;
                            case "country":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.country,
                                        field.getName(), field.getType()).build());
                                break;
                            case "department":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.department,
                                        field.getName(), field.getType()).build());
                                break;
                            case "businessPhones":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.businessPhones,
                                        field.getName(), field.getType()).build());
                                break;
                            case "givenName":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.givenName,
                                        field.getName(), field.getType()).build());
                                break;
                            case "onPremisesImmutableId":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.onPremisesImmutableId,
                                        field.getName(), field.getType()).build());
                                break;
                            case "jobTitle":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.jobTitle,
                                        field.getName(), field.getType()).build());
                                break;
                            case "mail":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.mail,
                                        field.getName(), field.getType()).build());
                                break;
                            case "mobilePhone":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.mobilePhone,
                                        field.getName(), field.getType()).build());
                                break;
                            case "preferredLanguage":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.preferredLanguage,
                                        field.getName(), field.getType()).build());
                                break;
                            case "officeLocation":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.officeLocation,
                                        field.getName(), field.getType()).build());
                                break;
                            case "postalCode":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.postalCode,
                                        field.getName(), field.getType()).build());
                                break;
                            case "state":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.state,
                                        field.getName(), field.getType()).build());
                                break;
                            case "streetAddress":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.streetAddress,
                                        field.getName(), field.getType()).build());
                                break;
                            case "surname":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.surname,
                                        field.getName(), field.getType()).build());
                                break;
                            case "usageLocation":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.usageLocation,
                                        field.getName(), field.getType()).build());
                                break;
                            case "companyName":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.companyName,
                                        field.getName(), field.getType()).build());
                                break;
                            case "creationType":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.creationType,
                                        field.getName(), field.getType()).build());
                                break;
                            case "employeeId":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.employeeId,
                                        field.getName(), field.getType()).build());
                                break;
                            case "onPremisesDistinguishedName":
                                attrs.add(AzureAttributes.
                                        doBuildAttributeFromClassField(user.onPremisesDistinguishedName,
                                                field.getName(), field.getType()).build());
                                break;
                            case "onPremisesSecurityIdentifier":
                                attrs.add(AzureAttributes.
                                        doBuildAttributeFromClassField(user.onPremisesSecurityIdentifier,
                                                field.getName(), field.getType()).build());
                                break;
                            case "showInAddressList":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.showInAddressList,
                                        field.getName(), field.getType()).build());
                                break;
                            case "proxyAddresses":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.proxyAddresses,
                                        field.getName(), field.getType()).build());
                                break;
                            case "userType":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.userType,
                                        field.getName(), field.getType()).build());
                                break;
                            case "otherMails":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.otherMails,
                                        field.getName(), field.getType()).build());
                                break;
                            case "provisionedPlans":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.provisionedPlans,
                                        field.getName(), field.getType()).build());
                                break;
                            case "assignedLicenses":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.assignedLicenses,
                                        field.getName(), field.getType()).build());
                                break;
                            case "assignedPlans":
                                attrs.add(AzureAttributes.doBuildAttributeFromClassField(user.assignedPlans,
                                        field.getName(), field.getType()).build());
                                break;
                            default:
                        }
                    }
                }
            }

            for (Attribute toAttribute : attrs) {
                String attributeName = toAttribute.getName();
                for (String attributeToGetName : attributesToGet) {
                    if (OperationalAttributes.ENABLE_NAME.equals(attributeToGetName)
                            && AzureAttributes.USER_ACCOUNT_ENABLED.equals(attributeName)) {
                        builder.addAttribute(OperationalAttributes.ENABLE_NAME, toAttribute.getValue());
                        break;
                    } else if (attributeName.equals(attributeToGetName)) {
                        builder.addAttribute(toAttribute);
                        break;
                    }
                }
            }
        } catch (IllegalArgumentException ex) {
            LOG.error(ex, "While converting to attributes");
        }

        if (attributesToGet.contains(PredefinedAttributes.GROUPS_NAME)) {
            List<String> groupNames = new ArrayList<>();
            List<Group> groups = client.getAuthenticated().getAllGroupsForUser(user.id);
            for (Group group : groups) {
                groupNames.add(group.mailNickname);
            }
            builder.addAttribute(AttributeBuilder.build(PredefinedAttributes.GROUPS_NAME, groupNames));
        }

        return builder.build();
    }

    private ConnectorObject fromGroup(final Group group, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.GROUP);
        builder.setUid(group.id);
        builder.setName(group.mailNickname);

        try {
            Set<Attribute> attrs = new HashSet<>();

            Field[] fields = Group.class.getDeclaredFields();
            for (Field field : fields) {
                field.setAccessible(true);
                switch (field.getName()) {
                    case "id":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.id,
                                field.getName(), field.getType()).build());
                        break;
                    case "mail":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.mail,
                                field.getName(), field.getType()).build());
                        break;
                    case "mailEnabled":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.mailEnabled,
                                field.getName(), field.getType()).build());
                        break;
                    case "onPremisesSecurityIdentifier":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.onPremisesSecurityIdentifier,
                                field.getName(), field.getType()).build());
                        break;
                    case "proxyAddresses":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.proxyAddresses,
                                field.getName(), field.getType()).build());
                        break;
                    case "description":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.description,
                                field.getName(), field.getType()).build());
                        break;
                    case "securityEnabled":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.securityEnabled,
                                field.getName(), field.getType()).build());
                        break;
                    case "classification":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.classification,
                                field.getName(), field.getType()).build());
                        break;
                    case "groupTypes":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.groupTypes,
                                field.getName(), field.getType()).build());
                        break;
                    case "preferredLanguage":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.preferredLanguage,
                                field.getName(), field.getType()).build());
                        break;
                    case "securityIdentifier":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.securityIdentifier,
                                field.getName(), field.getType()).build());
                        break;
                    case "theme":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.theme,
                                field.getName(), field.getType()).build());
                        break;
                    case "visibility":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.visibility,
                                field.getName(), field.getType()).build());
                        break;
                    default:
                }
            }
            for (Attribute toAttribute : attrs) {
                String attributeName = toAttribute.getName();
                for (String attributeToGetName : attributesToGet) {
                    if (attributeName.equals(attributeToGetName)) {
                        builder.addAttribute(toAttribute);
                        break;
                    }
                }
            }
        } catch (IllegalArgumentException ex) {
            LOG.error(ex, "While converting to attributes");
        }

        if (attributesToGet.contains(AzureAttributes.GROUP_ID)) {
            builder.addAttribute(AttributeBuilder.build(AzureAttributes.GROUP_ID, group.id));
        }

        return builder.build();
    }

    private ConnectorObject fromLicense(final SubscribedSku subscribedSku, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(new ObjectClass(AzureAttributes.AZURE_LICENSE_NAME));
        builder.setUid(subscribedSku.id);
        builder.setName(String.valueOf(subscribedSku.skuId));

        try {
            Set<Attribute> attrs = new HashSet<>();

            Field[] fields = SubscribedSku.class.getDeclaredFields();
            for (Field field : fields) {
                field.setAccessible(true);
                switch (field.getName()) {
                    case "id":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.id,
                                field.getName(), field.getType()).build());
                        break;
                    case "appliesTo":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.appliesTo,
                                field.getName(), field.getType()).build());
                        break;
                    case "capabilityStatus":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.capabilityStatus,
                                field.getName(), field.getType()).build());
                        break;
                    case "consumedUnits":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.consumedUnits,
                                field.getName(), field.getType()).build());
                        break;
                    case "prepaidUnits":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.prepaidUnits,
                                field.getName(), field.getType()).build());
                        break;
                    case "servicePlans":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.servicePlans,
                                field.getName(), field.getType()).build());
                        break;
                    case "skuPartNumber":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.skuPartNumber,
                                field.getName(), field.getType()).build());
                        break;
                    case "oDataType":
                        attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.oDataType,
                                field.getName(), field.getType()).build());
                        break;
                    default:
                }
            }
            for (Attribute toAttribute : attrs) {
                String attributeName = toAttribute.getName();
                for (String attributeToGetName : attributesToGet) {
                    if (attributeName.equals(attributeToGetName)) {
                        builder.addAttribute(toAttribute);
                        break;
                    }
                }
            }
        } catch (IllegalArgumentException ex) {
            LOG.error(ex, "While converting to attributes");
        }

        if (attributesToGet.contains(AzureAttributes.AZURE_LICENSE_NAME)) {
            builder.addAttribute(AttributeBuilder.build(AzureAttributes.AZURE_LICENSE_NAME, subscribedSku.id));
        }

        return builder.build();
    }

    private String getSkipToken(final UserCollectionRequestBuilder request) {
        String token = request.getRequestUrl().
                substring(request.getRequestUrl().indexOf(SKIP_TOKEN_ID) + SKIP_TOKEN_ID.length());
        return token.substring(0, token.indexOf("&"));
    }

    private String getGroupSkipToken(final GroupCollectionRequestBuilder request) {
        String token = request.getRequestUrl().
                substring(request.getRequestUrl().indexOf(SKIP_TOKEN_ID) + SKIP_TOKEN_ID.length());
        return token.substring(0, token.indexOf("&"));
    }

    @SuppressWarnings("unchecked")
    private void doUserSetAttribute(final String name, final List<Object> values, final User user) {
        Object value = values.isEmpty() ? null : values.get(0);
        switch (name) {
            case "displayName":
                user.displayName = (String) value;
                break;
            case "id":
                user.id = (String) value;
                break;
            case "city":
                user.city = (String) value;
                break;
            case "country":
                user.country = (String) value;
                break;
            case "department":
                user.department = (String) value;
                break;
            case "businessPhones":
                user.businessPhones = new ArrayList<>((List<String>) (List<?>) values);
                break;
            case "givenName":
                user.givenName = (String) value;
                break;
            case "onPremisesImmutableId":
                user.onPremisesImmutableId = (String) value;
                break;
            case "jobTitle":
                user.jobTitle = (String) value;
                break;
            case "mail":
                user.mail = (String) value;
                break;
            case "mobilePhone":
                user.mobilePhone = (String) value;
                break;
            case "passwordPolicies":
                user.passwordPolicies = (String) value;
                break;
            case "preferredLanguage":
                user.preferredLanguage = (String) value;
                break;
            case "officeLocation":
                user.officeLocation = (String) value;
                break;
            case "postalCode":
                user.postalCode = (String) value;
                break;
            case "state":
                user.state = (String) value;
                break;
            case "streetAddress":
                user.streetAddress = (String) value;
                break;
            case "surname":
                user.surname = (String) value;
                break;
            case "usageLocation":
                user.usageLocation = (String) value;
                break;
            case "userPrincipalName":
                user.userPrincipalName = (String) value;
                break;
            case "companyName":
                user.companyName = (String) value;
                break;
            case "creationType":
                user.creationType = (String) value;
                break;
            case "employeeId":
                user.employeeId = (String) value;
                break;
            case "onPremisesDistinguishedName":
                user.onPremisesDistinguishedName = (String) value;
                break;
            case "onPremisesSecurityIdentifier":
                user.onPremisesSecurityIdentifier = (String) value;
                break;
            case "showInAddressList":
                user.showInAddressList = (Boolean) value;
                break;
            case "proxyAddresses":
                user.proxyAddresses = new ArrayList<>((List<String>) (List<?>) values);
                break;
            case "userType":
                user.userType = (String) value;
                break;
            case "otherMails":
                user.otherMails = new ArrayList<>((List<String>) (List<?>) values);
                break;
            case "provisionedPlans":
                user.provisionedPlans = new ArrayList<>((List<ProvisionedPlan>) (List<?>) values);
                break;
            case "assignedLicenses":
                user.assignedLicenses = new ArrayList<>((List<AssignedLicense>) (List<?>) values);
                break;
            case "assignedPlans":
                user.assignedPlans = new ArrayList<>((List<AssignedPlan>) (List<?>) values);
                break;
            default:
        }
    }

    @SuppressWarnings("unchecked")
    private void doGroupSetAttribute(final String name, final List<Object> values, final Group group) {
        Object value = values.isEmpty() ? null : values.get(0);
        switch (name) {
            case "id":
                group.id = (String) value;
                break;
            case "mail":
                group.mail = (String) value;
                break;
            case "mailEnabled":
                group.mailEnabled = (Boolean) value;
                break;
            case "onPremisesSecurityIdentifier":
                group.onPremisesSecurityIdentifier = (String) value;
                break;
            case "proxyAddresses":
                group.proxyAddresses = new ArrayList<>((List<String>) (List<?>) values);
                break;
            case "description":
                group.description = (String) value;
                break;
            case "securityEnabled":
                group.securityEnabled = (Boolean) value;
                break;
            case "classification":
                group.classification = (String) value;
                break;
            case "groupTypes":
                group.groupTypes = new ArrayList<>((List<String>) (List<?>) values);
                break;
            case "preferredLanguage":
                group.preferredLanguage = (String) value;
                break;
            case "securityIdentifier":
                group.securityIdentifier = (String) value;
                break;
            case "theme":
                group.theme = (String) value;
                break;
            case "visibility":
                group.visibility = (String) value;
                break;
            default:
        }
    }
}
