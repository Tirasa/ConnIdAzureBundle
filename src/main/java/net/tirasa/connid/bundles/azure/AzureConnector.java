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
import com.microsoft.graph.models.DirectoryObjectCollectionResponse;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.models.GroupCollectionResponse;
import com.microsoft.graph.models.ProvisionedPlan;
import com.microsoft.graph.models.SubscribedSku;
import com.microsoft.graph.models.User;
import com.microsoft.graph.models.UserCollectionResponse;
import com.microsoft.graph.users.item.assignlicense.AssignLicensePostRequestBody;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
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

    private static final Log LOG = Log.getLog(AzureConnector.class);

    @SuppressWarnings("unchecked")
    private static void doUserSetAttribute(final String name, final List<Object> values, final User user) {
        Object value = values.isEmpty() ? null : values.get(0);
        switch (name) {
            case "displayName":
                user.setDisplayName((String) value);
                break;
            case "id":
                user.setId((String) value);
                break;
            case "city":
                user.setCity((String) value);
                break;
            case "country":
                user.setCountry((String) value);
                break;
            case "department":
                user.setDepartment((String) value);
                break;
            case "businessPhones":
                user.setBusinessPhones(new ArrayList<>((List<String>) (List<?>) values));
                break;
            case "givenName":
                user.setGivenName((String) value);
                break;
            case "onPremisesImmutableId":
                user.setOnPremisesImmutableId((String) value);
                break;
            case "jobTitle":
                user.setJobTitle((String) value);
                break;
            case "mail":
                user.setMail((String) value);
                break;
            case "mobilePhone":
                user.setMobilePhone((String) value);
                break;
            case "passwordPolicies":
                user.setPasswordPolicies((String) value);
                break;
            case "preferredLanguage":
                user.setPreferredLanguage((String) value);
                break;
            case "officeLocation":
                user.setOfficeLocation((String) value);
                break;
            case "postalCode":
                user.setPostalCode((String) value);
                break;
            case "state":
                user.setState((String) value);
                break;
            case "streetAddress":
                user.setStreetAddress((String) value);
                break;
            case "surname":
                user.setSurname((String) value);
                break;
            case "usageLocation":
                user.setUsageLocation((String) value);
                break;
            case "userPrincipalName":
                user.setUserPrincipalName((String) value);
                break;
            case "companyName":
                user.setCompanyName((String) value);
                break;
            case "creationType":
                user.setCreationType((String) value);
                break;
            case "employeeId":
                user.setEmployeeId((String) value);
                break;
            case "onPremisesDistinguishedName":
                user.setOnPremisesDistinguishedName((String) value);
                break;
            case "onPremisesSecurityIdentifier":
                user.setOnPremisesSecurityIdentifier((String) value);
                break;
            case "showInAddressList":
                user.setShowInAddressList((Boolean) value);
                break;
            case "proxyAddresses":
                user.setProxyAddresses(new ArrayList<>((List<String>) (List<?>) values));
                break;
            case "userType":
                user.setUserType((String) value);
                break;
            case "otherMails":
                user.setOtherMails(new ArrayList<>((List<String>) (List<?>) values));
                break;
            case "provisionedPlans":
                user.setProvisionedPlans(new ArrayList<>((List<ProvisionedPlan>) (List<?>) values));
                break;
            case "assignedLicenses":
                user.setAssignedLicenses(new ArrayList<>((List<AssignedLicense>) (List<?>) values));
                break;
            case "assignedPlans":
                user.setAssignedPlans(new ArrayList<>((List<AssignedPlan>) (List<?>) values));
                break;
            default:
        }
    }

    @SuppressWarnings("unchecked")
    private static void doGroupSetAttribute(final String name, final List<Object> values, final Group group) {
        Object value = values.isEmpty() ? null : values.get(0);
        switch (name) {
            case "id":
                group.setId((String) value);
                break;
            case "mail":
                group.setMail((String) value);
                break;
            case "mailEnabled":
                group.setMailEnabled((Boolean) value);
                break;
            case "onPremisesSecurityIdentifier":
                group.setOnPremisesSecurityIdentifier((String) value);
                break;
            case "proxyAddresses":
                group.setProxyAddresses(new ArrayList<>((List<String>) (List<?>) values));
                break;
            case "description":
                group.setDescription((String) value);
                break;
            case "securityEnabled":
                group.setSecurityEnabled((Boolean) value);
                break;
            case "classification":
                group.setClassification((String) value);
                break;
            case "groupTypes":
                group.setGroupTypes(new ArrayList<>((List<String>) (List<?>) values));
                break;
            case "preferredLanguage":
                group.setPreferredLanguage((String) value);
                break;
            case "securityIdentifier":
                group.setSecurityIdentifier((String) value);
                break;
            case "theme":
                group.setTheme((String) value);
                break;
            case "visibility":
                group.setVisibility((String) value);
                break;
            case AzureAttributes.GROUP_MAIL_NICKNAME:
                group.setMailNickname((String) value);
                break;
            case AzureAttributes.GROUP_DISPLAY_NAME:
                group.setDisplayName((String) value);
                break;
            case "allowExternalSenders":
                group.setAllowExternalSenders((Boolean) value);
                break;
            case "autoSubscribeNewMembers":
                group.setAutoSubscribeNewMembers((Boolean) value);
                break;
            case "preferredDataLocation":
                group.setPreferredDataLocation((String) value);
                break;
            default:
        }
    }

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
            LOG.error("Error with establishing connection while testing. " + "No instance of the configuration class");
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
                        UserCollectionResponse response;
                        if (StringUtil.isNotBlank(cookie)) {
                            response = client.getAuthenticated().getAllUsersNextPage(cookie);
                        } else {
                            response = client.getAuthenticated().getAllUsers(pagesSize);
                        }
                        users = response.getValue();
                        cookie = response.getOdataNextLink();
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
                        GroupCollectionResponse response;
                        if (StringUtil.isNotBlank(cookie)) {
                            response = client.getAuthenticated().getAllGroupsNextPage(cookie);
                        } else {
                            response = client.getAuthenticated().getAllGroups(pagesSize);
                        }
                        groups = response.getValue();
                        cookie = response.getOdataNextLink();
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
            return new Uid(directoryObject.getId());
        }

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            User user = new User();
            User createdUser = new User();
            String username = accessor.findString(AzureAttributes.USER_MAIL_NICKNAME);
            if (username == null) {
                username = accessor.findString(Name.NAME);
            }

            List<Object> licenses = accessor.findList(AzureAttributes.AZURE_LICENSE_NAME);

            // handle mandatory attributes (some attributes are handled by Service class)
            user.setDisplayName(accessor.findString(AzureAttributes.USER_DISPLAY_NAME));
            user.setMailNickname(username);

            accessor.getPassword().access(pwd -> user.setPasswordProfile(AzureUtils.createPassword(new String(pwd))));

            user.setAccountEnabled(accessor.getEnabled(true));

            createAttributes.stream().
                    filter(attribute -> attribute.getValue() != null).
                    forEach(attribute -> doUserSetAttribute(attribute.getName(), attribute.getValue(), user));
            try {
                createdUser = client.getAuthenticated().createUser(user);
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not create User : " + username, e);
            }

            // memberships
            List<Object> groups = accessor.findList(PredefinedAttributes.GROUPS_NAME);
            if (!CollectionUtil.isEmpty(groups)) {
                for (Object group : groups) {
                    try {
                        client.getAuthenticated().addUserToGroup(createdUser.getId(), group.toString());
                    } catch (Exception e) {
                        LOG.error("Could not add User {0} to Group {1} ", createdUser.getId(), group, e);
                    }
                }
            }

            // licenses
            if (!CollectionUtil.isEmpty(licenses)) {
                for (Object license : licenses) {
                    // executing an assignment per single license in order to skip errors from invalid licenses
                    AssignedLicense assignedLicense = new AssignedLicense();
                    assignedLicense.setSkuId(UUID.fromString(license.toString()));
                    AssignLicensePostRequestBody body = new AssignLicensePostRequestBody();
                    body.setAddLicenses(Collections.singletonList(assignedLicense));

                    try {
                        client.getAuthenticated().assignLicense(createdUser.getId(), body);
                    } catch (RuntimeException ex) {
                        LOG.error("While assigning license {0} to user {1}", license, createdUser, ex);
                    }
                }
            }

            return new Uid(createdUser.getId());
        }

        if (ObjectClass.GROUP.equals(objectClass)) {
            String groupName = accessor.findString(AzureAttributes.GROUP_MAIL_NICKNAME);
            if (groupName == null) {
                groupName = accessor.findString(Name.NAME);
            }
            String displayName = accessor.findString(AzureAttributes.GROUP_DISPLAY_NAME);

            Group group = new Group();
            // handle mandatory attributes (some attributes are handled by Service class)
            group.setDisplayName(displayName);
            group.setMailNickname(groupName);

            createAttributes.stream().filter(attribute -> attribute.getValue() != null).
                    forEach(attribute -> doGroupSetAttribute(attribute.getName(), attribute.getValue(), group));

            try {
                return new Uid(client.getAuthenticated().createGroup(group).getId());
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not create Group : " + groupName, e);
            }
        }

        LOG.warn("Create of type " + objectClass.getObjectClassValue() + " is not supported");
        throw new UnsupportedOperationException("Create of type"
                + objectClass.getObjectClassValue() + " is not supported");
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
                DirectoryObjectCollectionResponse groups =
                        client.getAuthenticated().getAllGroupsForUser(uid.getUidValue());

                while (groups != null) {
                    groups.getValue().stream().filter(Group.class::isInstance).map(Group.class::cast).
                            forEach(group -> client.getAuthenticated().
                            deleteUserFromGroup(uid.getUidValue(), group.getId()));

                    // Get the next page
                    String odataNextLink = groups.getOdataNextLink();
                    if (odataNextLink == null || odataNextLink.isEmpty()) {
                        break;
                    } else {
                        groups = client.getAuthenticated().getAllGroupsForUser(uid.getUidValue(), odataNextLink);
                    }
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
            user.setId(uid.getUidValue());

            if (status == null
                    || status.getValue() == null
                    || status.getValue().isEmpty()) {
                LOG.warn("{0} attribute value not correct, can't handle User status update",
                        OperationalAttributes.ENABLE_NAME);
            } else {
                user.setAccountEnabled(Boolean.valueOf(status.getValue().get(0).toString()));
            }

            try {
                replaceAttributes.stream().filter(attribute -> attribute.getValue() != null).
                        forEach(attribute -> doUserSetAttribute(attribute.getName(), attribute.getValue(), user));

                // password
                if (accessor.getPassword() != null) {
                    accessor.getPassword().
                            access(pwd -> user.setPasswordProfile(AzureUtils.createPassword(new String(pwd))));
                }

                client.getAuthenticated().updateUser(user);

                returnUid = new Uid(user.getId());
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not update User " + uid.getUidValue() + " from attributes ", e);
            }

            // memberships
            Set<String> ownGroups = new HashSet<>();
            try {
                DirectoryObjectCollectionResponse groups =
                        client.getAuthenticated().getAllGroupsForUser(uid.getUidValue());

                while (groups != null) {
                    groups.getValue().stream().filter(Group.class::isInstance).map(Group.class::cast).
                            forEach(group -> client.getAuthenticated().
                            deleteUserFromGroup(uid.getUidValue(), group.getId()));

                    // Get the next page
                    String odataNextLink = groups.getOdataNextLink();
                    if (odataNextLink == null || odataNextLink.isEmpty()) {
                        break;
                    } else {
                        groups = client.getAuthenticated().getAllGroupsForUser(uid.getUidValue(), odataNextLink);
                    }
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
                if (updatedUser.getAssignedLicenses() != null) {
                    for (AssignedLicense assignedLicense : updatedUser.getAssignedLicenses()) {
                        assignedSkuIds.add(assignedLicense.getSkuId());
                    }
                }

                if (CollectionUtil.isEmpty(licenses)) {
                    if (!assignedSkuIds.isEmpty()) {
                        AssignLicensePostRequestBody body = new AssignLicensePostRequestBody();
                        body.setRemoveLicenses(assignedSkuIds);

                        try {
                            client.getAuthenticated().assignLicense(user.getId(), body);
                        } catch (RuntimeException ex) {
                            LOG.error(ex, "While removing licenses from user {0}", user);
                        }
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
                            AssignedLicense assignedLicense = new AssignedLicense();
                            assignedLicense.setSkuId(newLicense);
                            AssignLicensePostRequestBody body = new AssignLicensePostRequestBody();
                            body.setAddLicenses(Collections.singletonList(assignedLicense));

                            // executing an assignment per single license in order to skip errors from invalid licenses
                            try {
                                client.getAuthenticated().assignLicense(user.getId(), body);
                            } catch (RuntimeException ex) {
                                LOG.error(ex, "While assigning license {0} to user {1}", newLicense, user);
                            }
                        }
                    }

                    if (!toRemove.isEmpty()) {
                        AssignLicensePostRequestBody body = new AssignLicensePostRequestBody();
                        body.setRemoveLicenses(toRemove);

                        try {
                            client.getAuthenticated().assignLicense(user.getId(), body);
                        } catch (RuntimeException ex) {
                            LOG.error(ex, "While removing licenses from user {0}", user);
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
            group.setId(uid.getUidValue());

            if (!uid.getUidValue().equals(groupID)) {
                LOG.info("Update - uid value different from Group ID");

                group.setMailNickname(mailNickname);
                group.setDisplayName(displayName);
            }

            try {
                replaceAttributes.stream().filter(attribute -> attribute.getValue() != null).
                        forEach(attribute -> doGroupSetAttribute(attribute.getName(), attribute.getValue(), group));
                client.getAuthenticated().updateGroup(group);

                returnUid = new Uid(group.getId());
            } catch (Exception e) {
                AzureUtils.wrapGeneralError("Could not update Group " + uid.getUidValue() + " from attributes ", e);
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
        builder.setUid(user.getId());
        builder.setName(user.getUserPrincipalName());

        try {
            Set<Attribute> attrs = new HashSet<>();

            Field[] fields = User.class.getDeclaredFields();
        
            // Support for newer Microsoft Graph SDK (v6.x+) that uses backingStore pattern
            // instead of accessible fields via reflection
            if (fields.length == 0) {
                // Build map of getter methods to attribute names
                Map<String, Method> attributeGetters = new HashMap<>();
                for (Method method : User.class.getMethods()) {
                    String methodName = method.getName();
                    if (methodName.startsWith("get") && method.getParameterCount() == 0 
                            && !methodName.equals("getClass")) {
                        String attributeName = methodName.substring(3);
                        if (attributeName.length() > 0) {
                            attributeName = attributeName.substring(0, 1).toLowerCase() 
                                    + attributeName.substring(1);
                            attributeGetters.put(attributeName, method);
                        }
                    }
                }
        
                // Special handling for passwordProfile and accountEnabled
                if (user.getPasswordProfile() != null && user.getPasswordProfile().getPassword() != null) {
                    attrs.add(AttributeBuilder.build(AzureAttributes.USER_PASSWORD_PROFILE,
                            new GuardedString(user.getPasswordProfile().getPassword().toCharArray())));
                }
                if (user.getAccountEnabled() != null) {
                    attrs.add(AttributeBuilder.build(AzureAttributes.USER_ACCOUNT_ENABLED, 
                            user.getAccountEnabled()));
                }
        
                // Process standard attributes via getters (matches all original switch cases)
                String[] standardAttributes = {
                    "displayName", "id", "userPrincipalName", "city", "country", "department",
                    "businessPhones", "givenName", "onPremisesImmutableId", "jobTitle", "mail",
                    "mobilePhone", "preferredLanguage", "officeLocation", "postalCode",
                    "streetAddress", "surname", "state", "usageLocation", "companyName",
                    "creationType", "employeeId", "onPremisesDistinguishedName",
                    "onPremisesSecurityIdentifier", "showInAddressList", "proxyAddresses",
                    "userType", "otherMails"
                };
        
                for (String attrName : standardAttributes) {
                    Method getter = attributeGetters.get(attrName);
                    if (getter != null) {
                        try {
                            Object value = getter.invoke(user);
                            if (value != null) {
                                Attribute attr = AzureAttributes.doBuildAttributeFromClassField(
                                        value, attrName, getter.getReturnType()).build();
                                if (attr.getValue() != null && !attr.getValue().isEmpty()) {
                                    attrs.add(attr);
                                }
                            }
                        } catch (ReflectiveOperationException e) {
                            LOG.warn("Error extracting attribute {0} via getter: {1}", attrName, e.getMessage());
                        }
                    }
                }
        
                // Special handling for collection attributes with transformations
                if (user.getProvisionedPlans() != null) {
                    List<String> provisionedPlans = user.getProvisionedPlans().stream()
                            .map(ProvisionedPlan::getService)
                            .collect(Collectors.toList());
                    attrs.add(AttributeBuilder.build("provisionedPlans", provisionedPlans));
                }
        
                if (user.getAssignedLicenses() != null) {
                    List<String> assignedLicenses = user.getAssignedLicenses().stream()
                            .map(assignedLicense -> assignedLicense.getSkuId() == null 
                                    ? "" : assignedLicense.getSkuId().toString())
                            .collect(Collectors.toList());
                    attrs.add(AttributeBuilder.build("assignedLicenses", assignedLicenses));
                }
        
                if (user.getAssignedPlans() != null) {
                    List<String> assignedPlans = user.getAssignedPlans().stream()
                            .map(assignedPlan -> assignedPlan.getServicePlanId() == null 
                                    ? "" : assignedPlan.getServicePlanId().toString())
                            .collect(Collectors.toList());
                    attrs.add(AttributeBuilder.build("assignedPlans", assignedPlans));
                }
            } else {
                // Original field-based approach for older SDK versions with accessible fields
                for (Field field : fields) {
                    if (field.getAnnotation(JsonIgnore.class) == null) {
                        field.setAccessible(true);
                        if (field.getName().equals(AzureAttributes.USER_PASSWORD_PROFILE)
                                && user.getPasswordProfile() != null 
                                && user.getPasswordProfile().getPassword() != null) {
                            attrs.add(AttributeBuilder.build(AzureAttributes.USER_PASSWORD_PROFILE,
                                    new GuardedString(user.getPasswordProfile().getPassword().toCharArray())));
                        } else if (field.getName().equals(AzureAttributes.USER_ACCOUNT_ENABLED)
                                && user.getAccountEnabled() != null) {
                            attrs.add(AttributeBuilder.build(AzureAttributes.USER_ACCOUNT_ENABLED, 
                                    user.getAccountEnabled()));
                        } else {
                            switch (field.getName()) {
                                case "displayName":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getDisplayName(), field.getName(), field.getType()).build());
                                    break;
                                case "id":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getId(), field.getName(), field.getType()).build());
                                    break;
                                case "userPrincipalName":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getUserPrincipalName(), field.getName(), field.getType()).build());
                                    break;
                                case "city":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getCity(), field.getName(), field.getType()).build());
                                    break;
                                case "country":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getCountry(), field.getName(), field.getType()).build());
                                    break;
                                case "department":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getDepartment(), field.getName(), field.getType()).build());
                                    break;
                                case "businessPhones":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getBusinessPhones(), field.getName(), field.getType()).build());
                                    break;
                                case "givenName":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getGivenName(), field.getName(), field.getType()).build());
                                    break;
                                case "onPremisesImmutableId":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getOnPremisesImmutableId(), field.getName(), field.getType()).build());
                                    break;
                                case "jobTitle":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getJobTitle(), field.getName(), field.getType()).build());
                                    break;
                                case "mail":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getMail(), field.getName(), field.getType()).build());
                                    break;
                                case "mobilePhone":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getMobilePhone(), field.getName(), field.getType()).build());
                                    break;
                                case "preferredLanguage":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getPreferredLanguage(), field.getName(), field.getType()).build());
                                    break;
                                case "officeLocation":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getOfficeLocation(), field.getName(), field.getType()).build());
                                    break;
                                case "postalCode":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getPostalCode(), field.getName(), field.getType()).build());
                                    break;
                                case "state":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getState(), field.getName(), field.getType()).build());
                                    break;
                                case "streetAddress":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getStreetAddress(), field.getName(), field.getType()).build());
                                    break;
                                case "surname":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getSurname(), field.getName(), field.getType()).build());
                                    break;
                                case "usageLocation":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getUsageLocation(), field.getName(), field.getType()).build());
                                    break;
                                case "companyName":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getCompanyName(), field.getName(), field.getType()).build());
                                    break;
                                case "creationType":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getCreationType(), field.getName(), field.getType()).build());
                                    break;
                                case "employeeId":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getEmployeeId(), field.getName(), field.getType()).build());
                                    break;
                                case "onPremisesDistinguishedName":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getOnPremisesDistinguishedName(), field.getName(), field.getType()).build());
                                    break;
                                case "onPremisesSecurityIdentifier":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getOnPremisesSecurityIdentifier(), field.getName(), field.getType()).build());
                                    break;
                                case "showInAddressList":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getShowInAddressList(), field.getName(), field.getType()).build());
                                    break;
                                case "proxyAddresses":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getProxyAddresses(), field.getName(), field.getType()).build());
                                    break;
                                case "userType":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getUserType(), field.getName(), field.getType()).build());
                                    break;
                                case "otherMails":
                                    attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                            user.getOtherMails(), field.getName(), field.getType()).build());
                                    break;
                                case "provisionedPlans":
                                    List<String> provisionedPlans = user.getProvisionedPlans() == null
                                            ? null
                                            : user.getProvisionedPlans().stream()
                                                    .map(ProvisionedPlan::getService)
                                                    .collect(Collectors.toList());
                                    attrs.add(AttributeBuilder.build(field.getName(), provisionedPlans));
                                    break;
                                case "assignedLicenses":
                                    List<String> assignedLicenses = user.getAssignedLicenses() == null
                                            ? null
                                            : user.getAssignedLicenses().stream()
                                                    .map(assignedLicense -> assignedLicense.getSkuId() == null
                                                            ? "" : assignedLicense.getSkuId().toString())
                                                    .collect(Collectors.toList());
                                    attrs.add(AttributeBuilder.build(field.getName(), assignedLicenses));
                                    break;
                                case "assignedPlans":
                                    List<String> assignedPlans = user.getAssignedPlans() == null
                                            ? null
                                            : user.getAssignedPlans().stream()
                                                    .map(assignedPlan -> assignedPlan.getServicePlanId() == null
                                                            ? "" : assignedPlan.getServicePlanId().toString())
                                                    .collect(Collectors.toList());
                                    attrs.add(AttributeBuilder.build(field.getName(), assignedPlans));
                                    break;
                                default:
                            }
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
            DirectoryObjectCollectionResponse groups = client.getAuthenticated().getAllGroupsForUser(user.getId());

            List<String> groupNames = new ArrayList<>();
            while (groups != null) {
                groups.getValue().stream().filter(Group.class::isInstance).map(Group.class::cast).
                        forEach(group -> groupNames.add(group.getMailNickname()));

                // Get the next page
                String odataNextLink = groups.getOdataNextLink();
                if (odataNextLink == null || odataNextLink.isEmpty()) {
                    break;
                } else {
                    groups = client.getAuthenticated().getAllGroupsForUser(user.getId(), odataNextLink);
                }
            }
            builder.addAttribute(AttributeBuilder.build(PredefinedAttributes.GROUPS_NAME, groupNames));
        }

        return builder.build();
    }

    private ConnectorObject fromGroup(final Group group, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.GROUP);
        builder.setUid(group.getId());
        builder.setName(group.getMailNickname());

        try {
            Set<Attribute> attrs = new HashSet<>();

            Field[] fields = Group.class.getDeclaredFields();
        
            // Support for newer Microsoft Graph SDK (v6.x+) using backingStore pattern
            if (fields.length == 0) {
                // Build map of getter methods to attribute names
                Map<String, Method> attributeGetters = new HashMap<>();
                for (Method method : Group.class.getMethods()) {
                    String methodName = method.getName();
                    if (methodName.startsWith("get") && method.getParameterCount() == 0 
                            && !methodName.equals("getClass")) {
                        String attributeName = methodName.substring(3);
                        if (attributeName.length() > 0) {
                            attributeName = attributeName.substring(0, 1).toLowerCase() 
                                    + attributeName.substring(1);
                            attributeGetters.put(attributeName, method);
                        }
                    }
                }
        
                // Process standard attributes via getters
                String[] standardAttributes = {
                    "id", "mail", "mailEnabled", "onPremisesSecurityIdentifier", "proxyAddresses",
                    "description", "securityEnabled", "classification", "groupTypes", "preferredLanguage",
                    "securityIdentifier", "theme", "visibility", "mailNickname", "displayName",
                    "allowExternalSenders", "autoSubscribeNewMembers", "preferredDataLocation"
                };
        
                for (String attrName : standardAttributes) {
                    Method getter = attributeGetters.get(attrName);
                    if (getter != null) {
                        try {
                            Object value = getter.invoke(group);
                            if (value != null) {
                                Attribute attr = AzureAttributes.doBuildAttributeFromClassField(
                                        value, attrName, getter.getReturnType()).build();
                                if (attr.getValue() != null && !attr.getValue().isEmpty()) {
                                    attrs.add(attr);
                                }
                            }
                        } catch (ReflectiveOperationException e) {
                            LOG.warn("Error extracting attribute {0} via getter: {1}", attrName, e.getMessage());
                        }
                    }
                }
            } else {
                // Original field-based approach for older SDK versions
                for (Field field : fields) {
                    field.setAccessible(true);
                    switch (field.getName()) {
                        case "id":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getId(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "mail":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getMail(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "mailEnabled":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getMailEnabled(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "onPremisesSecurityIdentifier":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(
                                    group.getOnPremisesSecurityIdentifier(), field.getName(), field.getType()).build());
                            break;
                        case "proxyAddresses":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getProxyAddresses(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "description":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getDescription(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "securityEnabled":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getSecurityEnabled(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "classification":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getClassification(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "groupTypes":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getGroupTypes(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "preferredLanguage":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getPreferredLanguage(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "securityIdentifier":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getSecurityIdentifier(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "theme":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getTheme(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "visibility":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getVisibility(),
                                    field.getName(), field.getType()).build());
                            break;
                        case AzureAttributes.GROUP_MAIL_NICKNAME:
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getMailNickname(),
                                    field.getName(), field.getType()).build());
                            break;
                        case AzureAttributes.GROUP_DISPLAY_NAME:
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getDisplayName(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "allowExternalSenders":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getAllowExternalSenders(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "autoSubscribeNewMembers":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getAutoSubscribeNewMembers(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "preferredDataLocation":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(group.getPreferredDataLocation(),
                                    field.getName(), field.getType()).build());
                            break;
                        default:
                    }
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
            builder.addAttribute(AttributeBuilder.build(AzureAttributes.GROUP_ID, group.getId()));
        }

        if (attributesToGet.contains(PredefinedAttributes.GROUPS_NAME)) {
            List<String> groupNames = client.getAuthenticated().getAllGroupsForGroup(group.getId()).
                    stream().map(Group::getMailNickname).
                    collect(Collectors.toList());
            builder.addAttribute(AttributeBuilder.build(PredefinedAttributes.GROUPS_NAME, groupNames));
        }

        return builder.build();
    }

    private ConnectorObject fromLicense(final SubscribedSku subscribedSku, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(new ObjectClass(AzureAttributes.AZURE_LICENSE_NAME));
        builder.setUid(subscribedSku.getId());
        builder.setName(String.valueOf(subscribedSku.getSkuId()));

        try {
            Set<Attribute> attrs = new HashSet<>();
            
            Field[] fields = SubscribedSku.class.getDeclaredFields();
            
            // Support for newer Microsoft Graph SDK (v6.x+) using backingStore pattern
            if (fields.length == 0) {
                Map<String, Method> attributeGetters = new HashMap<>();
                for (Method method : SubscribedSku.class.getMethods()) {
                    String methodName = method.getName();
                    if (methodName.startsWith("get") && method.getParameterCount() == 0 
                            && !methodName.equals("getClass")) {
                        String attributeName = methodName.substring(3);
                        if (attributeName.length() > 0) {
                            attributeName = attributeName.substring(0, 1).toLowerCase() 
                                    + attributeName.substring(1);
                            attributeGetters.put(attributeName, method);
                        }
                    }
                }
        
                String[] standardAttributes = {
                    "id", "appliesTo", "capabilityStatus", "consumedUnits", 
                    "prepaidUnits", "servicePlans", "skuPartNumber", "odataType"
                };
        
                for (String attrName : standardAttributes) {
                    Method getter = attributeGetters.get(attrName);
                    if (getter != null) {
                        try {
                            Object value = getter.invoke(subscribedSku);
                            if (value != null) {
                                Attribute attr = AzureAttributes.doBuildAttributeFromClassField(
                                        value, attrName, getter.getReturnType()).build();
                                if (attr.getValue() != null && !attr.getValue().isEmpty()) {
                                    attrs.add(attr);
                                }
                            }
                        } catch (ReflectiveOperationException e) {
                            LOG.warn("Error extracting attribute {0} via getter: {1}", attrName, e.getMessage());
                        }
                    }
                }
            } else {
                // Original field-based approach for older SDK versions
                for (Field field : fields) {
                    field.setAccessible(true);
                    switch (field.getName()) {
                        case "id":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.getId(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "appliesTo":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.getAppliesTo(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "capabilityStatus":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.getCapabilityStatus(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "consumedUnits":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.getConsumedUnits(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "prepaidUnits":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.getPrepaidUnits(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "servicePlans":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.getServicePlans(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "skuPartNumber":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.getSkuPartNumber(),
                                    field.getName(), field.getType()).build());
                            break;
                        case "oDataType":
                            attrs.add(AzureAttributes.doBuildAttributeFromClassField(subscribedSku.getOdataType(),
                                    field.getName(), field.getType()).build());
                            break;
                        default:
                    }
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
            builder.addAttribute(AttributeBuilder.build(AzureAttributes.AZURE_LICENSE_NAME, subscribedSku.getId()));
        }

        return builder.build();
    }
}
