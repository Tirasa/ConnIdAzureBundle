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
package net.tirasa.connid.bundles.azure;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import net.tirasa.connid.bundles.azure.dto.Group;
import net.tirasa.connid.bundles.azure.dto.PagedGroups;
import net.tirasa.connid.bundles.azure.dto.PagedUsers;
import net.tirasa.connid.bundles.azure.dto.User;
import net.tirasa.connid.bundles.azure.service.AzureService;
import net.tirasa.connid.bundles.azure.utils.AzureAttributes;
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
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
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
        Connector, CreateOp, DeleteOp, SchemaOp, SearchOp<Filter>, TestOp, UpdateOp {

    private AzureConnectorConfiguration configuration;

    private Schema schema;

    private static final Log LOG = Log.getLog(AzureConnector.class);

    private AzureService client;

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(Configuration configuration) {
        LOG.ok("Init");

        this.configuration = (AzureConnectorConfiguration) configuration;
        this.configuration.validate();

        client = new AzureService(
                this.configuration.getAuthority(),
                this.configuration.getClientId(),
                this.configuration.getUsername(),
                this.configuration.getPassword(),
                this.configuration.getResourceURI(),
                this.configuration.getDomain()
        );

        LOG.ok("Connector {0} successfully inited", getClass().getName());
    }

    @Override
    public void dispose() {
        LOG.ok("Configuration cleanup");

        configuration = null;
    }

    @Override
    public void test() {
        LOG.ok("Test connector");

        if (configuration != null) {

            if (client.getAuthenticated() != null) {
                LOG.ok("Test was successfull");
            } else {
                LOG.error("Error with establishing connection while testing. No authorization data were provided.");
            }

        } else {
            LOG.error("Error with establishing connection while testing. "
                    + "No instance of the configuration class");
        }
    }

    @Override
    public Schema schema() {
        LOG.ok("Building schema definition ");

        if (schema == null) {
            schema = AzureAttributes.buildSchema();
        }
        return schema;
    }

    @Override
    public FilterTranslator<Filter> createFilterTranslator(
            final ObjectClass objectClass,
            final OperationOptions options) {

        return new FilterTranslator<Filter>() {

            @Override
            public List<Filter> translate(final Filter filter) {
                return Collections.singletonList(filter);
            }
        };
    }

    @Override
    public void executeQuery(ObjectClass objectClass, Filter query, ResultsHandler handler, OperationOptions options) {
        LOG.ok("Connector object execute query ");

        Attribute key = null;
        if (query instanceof EqualsFilter) {
            Attribute filterAttr = ((EqualsFilter) query).getAttribute();
            if (filterAttr instanceof Uid) {
                key = filterAttr;
            } else if (ObjectClass.ACCOUNT.equals(objectClass) || ObjectClass.GROUP.equals(objectClass)) {
                key = filterAttr;
            }
        }

        Set<String> attributesToGet = new HashSet<>();
        if (options.getAttributesToGet() != null) {
            attributesToGet.addAll(Arrays.asList(options.getAttributesToGet()));
        }

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            if (key == null) {
                List<User> users = null;
                int remainingResults = -1;
                int pagesSize = options.getPageSize() != null ? options.getPageSize() : -1;
                String cookie = options.getPagedResultsCookie();

                try {
                    if (pagesSize != -1) {
                        if (StringUtil.isNotBlank(cookie)) {
                            PagedUsers pagedResult =
                                    client.getAuthenticated().getAllUsersNextPage(pagesSize, cookie, false);
                            users = pagedResult.getUsers();

                            cookie = users.size() > pagesSize ? pagedResult.getSkipToken() : null;
                        } else {
                            PagedUsers pagedResult = client.getAuthenticated().getAllUsers(pagesSize);
                            users = pagedResult.getUsers();

                            cookie = pagedResult.getSkipToken();
                        }
                    } else {
                        users = client.getAuthenticated().getAllUsers();
                    }
                } catch (Exception e) {
                    AzureUtils.wrapGeneralError("While getting users!", e);
                }

                for (User user : users) {
                    handler.handle(fromUser(user, attributesToGet));
                }

                if (handler instanceof SearchResultsHandler) {
                    ((SearchResultsHandler) handler).handleResult(new SearchResult(cookie, remainingResults));
                }
            } else {
                if (Uid.NAME.equals(key.getName()) || AzureAttributes.USER_ID.equals(key.getName())) {
                    User result = null;
                    try {
                        result = client.getAuthenticated().getUser(AttributeUtil.getAsStringValue(key));
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError("While getting User : "
                                + key.getName() + " - " + AttributeUtil.getAsStringValue(key), e);
                    }
                    handler.handle(fromUser(result, attributesToGet));
                }
            }

        } else if (ObjectClass.GROUP.equals(objectClass)) {
            if (key == null) {
                List<Group> groups = null;
                int remainingResults = -1;
                int pagesSize = options.getPageSize() != null ? options.getPageSize() : -1;
                String cookie = options.getPagedResultsCookie();

                try {
                    if (pagesSize != -1) {
                        if (StringUtil.isNotBlank(cookie)) {
                            PagedGroups pagedResult =
                                    client.getAuthenticated().getAllGroupsNextPage(pagesSize, cookie, false);
                            groups = pagedResult.getGroups();

                            cookie = groups.size() > pagesSize ? pagedResult.getSkipToken() : null;
                        } else {
                            PagedGroups pagedResult = client.getAuthenticated().getAllGroups(pagesSize);
                            groups = pagedResult.getGroups();

                            cookie = pagedResult.getSkipToken();
                        }
                    } else {
                        groups = client.getAuthenticated().getAllGroups();
                    }
                } catch (Exception e) {
                    AzureUtils.wrapGeneralError("While getting groups!", e);
                }

                for (Group group : groups) {
                    handler.handle(fromGroup(group, attributesToGet));
                }

                if (handler instanceof SearchResultsHandler) {
                    ((SearchResultsHandler) handler).handleResult(new SearchResult(cookie, remainingResults));
                }

            } else {
                if (Uid.NAME.equals(key.getName()) || AzureAttributes.GROUP_ID.equals(key.getName())) {
                    Group result = null;
                    try {
                        result = client.getAuthenticated().getGroup(AttributeUtil.getAsStringValue(key));
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError("While getting group!", e);
                    }
                    handler.handle(fromGroup(result, attributesToGet));
                }
            }
        } else {
            LOG.warn("Search of type {0} is not supported", objectClass.getObjectClassValue());
            throw new UnsupportedOperationException("Search of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }

    }

    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> createAttributes, OperationOptions options) {
        LOG.ok("Resource object create ");

        if (createAttributes == null || createAttributes.isEmpty()) {
            AzureUtils.handleGeneralError("Set of Attributes value is null or empty");
        }

        final AttributesAccessor accessor = new AttributesAccessor(createAttributes);

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            User user = new User();
            String username = accessor.findString(AzureAttributes.USER_MAIL_NICKNAME);
            if (username == null) {
                username = accessor.findString(Name.NAME);
            }
            GuardedString password = accessor.findGuardedString(OperationalAttributes.PASSWORD_NAME);
            String displayName = accessor.findString(AzureAttributes.USER_DISPLAY_NAME);
            Attribute status = accessor.find(OperationalAttributes.ENABLE_NAME);

            try {
                // handle mandatory attributes (some attributes are handled by Service class)
                user.setDisplayName(displayName);
                user.setMailNickname(username);
                user.setPassword(password);

                if (status == null
                        || status.getValue() == null
                        || status.getValue().isEmpty()) {
                    LOG.warn("{0} attribute value not correct or not found, won't handle user status",
                            OperationalAttributes.ENABLE_NAME);
                } else {
                    user.setAccountEnabled(Boolean.parseBoolean(status.getValue().get(0).toString()));
                }

                user.fromAttributes(createAttributes);
                client.getAuthenticated().createUser(user);
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not create user : " + username, e);
            }

            List<Object> groups = accessor.findList(PredefinedAttributes.GROUPS_NAME);
            if (!CollectionUtil.isEmpty(groups)) {
                for (Object group : groups) {
                    try {
                        client.getAuthenticated().addUserToGroup(user.getObjectId(), group.toString());
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError(
                                "Could not add user :" + user.getObjectId() + " to group :" + group, e);
                    }
                }
            }

            return new Uid(user.getObjectId());

        } else if (ObjectClass.GROUP.equals(objectClass)) {
            String groupName = accessor.findString(AzureAttributes.GROUP_MAIL_NICKNAME);
            if (groupName == null) {
                groupName = accessor.findString(Name.NAME);
            }
            String displayName = accessor.findString(AzureAttributes.GROUP_DISPLAY_NAME);

            Group group = new Group();
            try {
                // handle mandatory attributes (some attributes are handled by Service class)
                group.setDisplayName(displayName);
                group.setMailNickname(groupName);

                group.fromAttributes(createAttributes);
                client.getAuthenticated().createGroup(group);
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not create group : " + groupName, e);
            }

            return new Uid(group.getObjectId());

        } else {
            LOG.warn("Create of type {0} is not supported", objectClass.getObjectClassValue());
            throw new UnsupportedOperationException("Create of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }
    }

    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
        LOG.ok("Resource object delete ");

        if (StringUtil.isBlank(uid.getUidValue())) {
            LOG.error("Uid not provided or empty ");
            throw new InvalidAttributeValueException("Uid value not provided or empty");
        }

        if (objectClass == null) {
            LOG.error("Object value not provided {0} ", objectClass);
            throw new InvalidAttributeValueException("Object value not provided");
        }

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            try {
                for (Group group : client.getAuthenticated().getAllGroupsForUser(uid.getUidValue())) {
                    client.getAuthenticated().deleteUserFromGroup(uid.getUidValue(), group.getObjectId());
                }
            } catch (Exception e) {
                LOG.error("Could not delete user {0} from groups", uid.getUidValue());
            }

            try {
                client.getAuthenticated().deleteUser(uid.getUidValue());
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not delete user " + uid.getUidValue(), e);
            }

        } else if (ObjectClass.GROUP.equals(objectClass)) {
            try {
                client.getAuthenticated().deleteGroup(uid.getUidValue());
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not delete group " + uid.getUidValue(), e);
            }

        } else {
            LOG.warn("Delete of type {0} is not supported", objectClass.getObjectClassValue());
            throw new UnsupportedOperationException("Delete of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }

    }

    @Override
    public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> replaceAttributes, OperationOptions options) {
        LOG.ok("Resource object update ");

        if (replaceAttributes == null || replaceAttributes.isEmpty()) {
            AzureUtils.handleGeneralError("Set of Attributes value is null or empty");
        }

        final AttributesAccessor accessor = new AttributesAccessor(replaceAttributes);

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            Uid returnUid = uid;

            // username
            String userID = accessor.findString(AzureAttributes.USER_ID);
            if (userID == null) {
                userID = accessor.findString(Name.NAME);
            }
            String mailNickname = accessor.findString(AzureAttributes.USER_MAIL_NICKNAME);
            String displayName = accessor.findString(AzureAttributes.USER_DISPLAY_NAME);
            Attribute status = accessor.find(OperationalAttributes.ENABLE_NAME);

            if (displayName == null) {
                AzureUtils.handleGeneralError("The "
                        + AzureAttributes.USER_DISPLAY_NAME
                        + " property cannot be cleared during updates");
            }

            User user = new User();
            user.setObjectId(uid.getUidValue());

            if (!uid.getUidValue().equals(userID)) {
                LOG.info("Update - uid value different from user ID");

                user.setDisplayName(displayName);
                user.setMailNickname(mailNickname);
            }

            if (status == null
                    || status.getValue() == null
                    || status.getValue().isEmpty()) {
                LOG.warn("{0} attribute value not correct, can't handle user status update",
                        OperationalAttributes.ENABLE_NAME);
            } else {
                user.setAccountEnabled(Boolean.parseBoolean(status.getValue().get(0).toString()));
            }

            try {
                user.fromAttributes(replaceAttributes);

                // password
                GuardedString password = accessor.getPassword();
                if (password != null) {
                    try {
                        if (user.getPassword() != null || user.getPasswordProfile() != null) {
                            user.setPassword(password);
                        }
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError(
                                "Could not update password for user " + uid.getUidValue(), e);
                    }
                }

                client.getAuthenticated().updateUser(user);

                returnUid = new Uid(user.getObjectId());
            } catch (Exception e) {
                AzureUtils.wrapGeneralError(
                        "Could not create User " + uid.getUidValue() + " from attributes ", e);
            }

            // memberships
            Set<String> ownGroups = new HashSet<>();
            try {
                List<Group> ownGroupsResults =
                        client.getAuthenticated().getAllGroupsForUser(returnUid.getUidValue());
                for (Group group : ownGroupsResults) {
                    ownGroups.add(group.getObjectId());
                }
            } catch (Exception ex) {
                LOG.error(ex, "Could not list groups for user {0}", uid.getUidValue());
            }

            List<Object> groups = CollectionUtil.nullAsEmpty(accessor.findList(PredefinedAttributes.GROUPS_NAME));
            for (Object group : groups) {
                if (!ownGroups.contains(group.toString())) {
                    try {
                        client.getAuthenticated().addUserToGroup(returnUid.getUidValue(), group.toString());
                        LOG.info("User added to group: {0} after update", group);
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError(
                                "Could not add group : " + group + " to user : " + returnUid.getUidValue(), e);
                    }
                }
            }
            for (String group : ownGroups) {
                if (!groups.contains(group)) {
                    try {
                        client.getAuthenticated().deleteUserFromGroup(returnUid.getUidValue(), group);
                        LOG.info("User removed from group: {0} after update", group);
                    } catch (Exception e) {
                        AzureUtils.wrapGeneralError(
                                "Could not remove group : " + group + " to user : " + returnUid.getUidValue(), e);
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
            group.setObjectId(uid.getUidValue());

            if (!uid.getUidValue().equals(groupID)) {
                LOG.info("Update - uid value different from group ID");

                group.setMailNickname(mailNickname);
                group.setDisplayName(displayName);
            }

            try {
                group.fromAttributes(replaceAttributes);
                client.getAuthenticated().updateGroup(group);

                returnUid = new Uid(group.getObjectId());
            } catch (Exception e) {
                AzureUtils.wrapGeneralError(
                        "Could not create Group " + uid.getUidValue() + " from attributes ", e);
            }

            return returnUid;

        } else {
            LOG.warn("Update of type {0} is not supported", objectClass.getObjectClassValue());
            throw new UnsupportedOperationException("Update of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }
    }

    public AzureService getClient() {
        return client;
    }

    private ConnectorObject fromUser(final User user, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.ACCOUNT);
        builder.setUid(user.getObjectId());
        builder.setName(user.getMailNickname());

        try {
            for (Attribute toAttribute : user.toAttributes()) {
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
        } catch (IllegalArgumentException | IllegalAccessException ex) {
            LOG.error(ex, "While converting to attributes");
        }

        if (attributesToGet.contains(PredefinedAttributes.GROUPS_NAME)) {
            List<String> groupNames = new ArrayList<>();
            List<Group> groups = client.getAuthenticated().getAllGroupsForUser(user.getObjectId());
            for (Group group : groups) {
                groupNames.add(group.getMailNickname());
            }
            builder.addAttribute(AttributeBuilder.build(PredefinedAttributes.GROUPS_NAME, groupNames));
        }

        return builder.build();
    }

    private ConnectorObject fromGroup(final Group group, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.GROUP);
        builder.setUid(group.getObjectId());
        builder.setName(group.getMailNickname());

        try {
            for (Attribute toAttribute : group.toAttributes()) {
                String attributeName = toAttribute.getName();
                for (String attributeToGetName : attributesToGet) {
                    if (attributeName.equals(attributeToGetName)) {
                        builder.addAttribute(toAttribute);
                        break;
                    }
                }
            }
        } catch (IllegalArgumentException | IllegalAccessException ex) {
            LOG.error(ex, "While converting to attributes");
        }

        if (attributesToGet.contains(AzureAttributes.GROUP_ID)) {
            builder.addAttribute(AttributeBuilder.build(AzureAttributes.GROUP_ID, group.getObjectId()));
        }

        return builder.build();
    }
}
