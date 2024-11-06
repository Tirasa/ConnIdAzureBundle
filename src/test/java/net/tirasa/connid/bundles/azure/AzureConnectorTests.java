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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.microsoft.graph.models.AssignedLicense;
import com.microsoft.graph.models.DirectoryObject;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.models.User;
import com.microsoft.graph.models.UserCollectionResponse;
import com.microsoft.graph.models.odataerrors.ODataError;
import com.microsoft.graph.users.item.assignlicense.AssignLicensePostRequestBody;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import net.tirasa.connid.bundles.azure.service.AzureClient;
import net.tirasa.connid.bundles.azure.utils.AzureAttributes;
import net.tirasa.connid.bundles.azure.utils.AzureFilter;
import net.tirasa.connid.bundles.azure.utils.AzureFilterOp;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.PredefinedAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.SortKey;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.test.common.TestHelpers;
import org.identityconnectors.test.common.ToListResultsHandler;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class AzureConnectorTests {

    private static final Log LOG = Log.getLog(AzureConnectorTests.class);

    private static final Properties PROPS = new Properties();

    private static AzureConnectorConfiguration CONF;

    private static AzureConnector CONN;

    protected static ConnectorFacade CONNECTOR;

    private static String VALID_LICENSE;

    private static String USAGE_LOCATION;

    @BeforeAll
    public static void setUpConf() throws IOException {
        PROPS.load(AzureConnectorTests.class.getResourceAsStream(
                "/net/tirasa/connid/bundles/azure/oauth2.properties"));

        Map<String, String> configurationParameters = new HashMap<>();
        for (final String name : PROPS.stringPropertyNames()) {
            configurationParameters.put(name, PROPS.getProperty(name));
        }
        CONF = AzureConnectorTestsUtils.buildConfiguration(configurationParameters);

        Boolean isValid = AzureConnectorTestsUtils.isConfigurationValid(CONF);
        if (isValid) {
            CONN = new AzureConnector();
            CONN.init(CONF);
            try {
                CONN.test();
            } catch (Exception e) {
                LOG.error(e, "While testing connector");
            }
            CONN.schema();
        }

        CONNECTOR = newFacade();

        VALID_LICENSE = PROPS.getProperty("availableLicense");
        USAGE_LOCATION = PROPS.getProperty("usageLocation");

        assertNotNull(CONF);
        assertNotNull(isValid);
        assertNotNull(CONF.getAuthority());
        assertNotNull(CONF.getClientId());
        assertNotNull(CONF.getDomain());
        assertNotNull(CONF.getPassword());
        assertNotNull(CONF.getRedirectURI());
        assertNotNull(CONF.getResourceURI());
        assertNotNull(CONF.getUsername());
        assertNotNull(CONF.getTenantId());
        assertNotNull(CONF.getClientSecret());
        assertNotNull(CONF.getScopes());
    }

    private boolean testLicenses() {
        return VALID_LICENSE != null && USAGE_LOCATION != null;
    }

    private static ConnectorFacade newFacade() {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        APIConfiguration impl = TestHelpers.createTestConfiguration(AzureConnector.class, CONF);
        impl.getResultsHandlerConfiguration().setFilteredResultsHandlerInValidationMode(true);
        return factory.newInstance(impl);
    }

    private AzureClient newClient() {
        return CONN.getClient();
    }

    @Test
    public void validate() {
        newFacade().validate();
    }

    @Test
    public void schema() {
        Schema schema = newFacade().schema();
        assertEquals(2, schema.getObjectClassInfo().size());

        boolean accountFound = false;
        boolean groupFound = false;
        for (ObjectClassInfo oci : schema.getObjectClassInfo()) {
            if (ObjectClass.ACCOUNT_NAME.equals(oci.getType())) {
                accountFound = true;
            } else if (ObjectClass.GROUP_NAME.equals(oci.getType())) {
                groupFound = true;
            }
        }
        assertTrue(accountFound);
        assertTrue(groupFound);
    }

    @Test
    public void search() {
        ToListResultsHandler handler = new ToListResultsHandler();

        SearchResult result = CONNECTOR.
                search(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertNotNull(result);
        assertNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());

        assertFalse(handler.getObjects().isEmpty());

        result = CONNECTOR.
                search(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().setPageSize(1).build());

        assertNotNull(result);
        assertNotNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());
    }

    private void cleanup(
            final ConnectorFacade connector,
            final AzureClient client,
            final String testUserUid,
            final String testGroupUid) {
        if (testUserUid != null) {
            connector.delete(ObjectClass.ACCOUNT, new Uid(testUserUid), new OperationOptionsBuilder().build());
            try {
                client.getAuthenticated().deleteUser(testUserUid);
                fail(); // must fail
            } catch (RuntimeException e) {
                assertNotNull(e);
            }

            try {
                client.getAuthenticated().getUser(testUserUid);
                fail(); // must fail
            } catch (ODataError e) {
                assertNotNull(e);
            }
        }

        if (testGroupUid != null) {
            connector.delete(ObjectClass.GROUP, new Uid(testGroupUid), new OperationOptionsBuilder().build());
            try {
                client.getAuthenticated().deleteGroup(testGroupUid);
                fail(); // must fail
            } catch (RuntimeException e) {
                assertNotNull(e);
            }

            try {
                client.getAuthenticated().getGroup(testGroupUid);
                fail(); // must fail
            } catch (ODataError e) {
                assertNotNull(e);
            }
        }
    }

    private void cleanup(
            final AzureClient client,
            final String testUserUid,
            final String testGroupUid) {
        if (testUserUid != null) {
            client.getAuthenticated().deleteUser(testUserUid);

            try {
                client.getAuthenticated().getUser(testUserUid);
                fail(); // must fail
            } catch (RuntimeException e) {
                assertNotNull(e);
            }
        }

        if (testGroupUid != null) {
            client.getAuthenticated().deleteGroup(testGroupUid);

            try {
                client.getAuthenticated().getGroup(testGroupUid);
                fail(); // must fail
            } catch (RuntimeException e) {
                assertNotNull(e);
            }
        }
    }

    @Test
    public void crud() {
        ConnectorFacade connector = newFacade();
        AzureClient client = newClient();

        String testGroupUid = null;
        String testUserUid = null;
        try {
            // CREATE GROUP
            String groupName = UUID.randomUUID().toString();

            Set<Attribute> groupAttrs = new HashSet<>();
            groupAttrs.add(AttributeBuilder.build(AzureAttributes.GROUP_DISPLAY_NAME, groupName));
            groupAttrs.add(AttributeBuilder.build(AzureAttributes.GROUP_MAIL_NICKNAME, groupName));
            groupAttrs.add(AttributeBuilder.build(AzureAttributes.GROUP_MAIL_ENABLED, false));
            groupAttrs.add(AttributeBuilder.build(AzureAttributes.GROUP_SECURITY_ENABLED, true));
            groupAttrs.add(AttributeBuilder.build("description", "Description test"));

            Uid created = connector.create(ObjectClass.GROUP, groupAttrs, new OperationOptionsBuilder().build());
            assertNotNull(created);

            testGroupUid = created.getUidValue();

            // GET GROUP
            Group group = client.getAuthenticated().getGroup(testGroupUid);
            assertNotNull(group);
            assertEquals(group.getId(), testGroupUid);

            LOG.info("Created Group with name {0} on service!", group.getDisplayName());

            // CREATE USER
            String username = UUID.randomUUID().toString();
            Attribute password = AttributeBuilder.buildPassword(new GuardedString("Password123".toCharArray()));
            Attribute newPassword = AttributeBuilder.buildPassword(new GuardedString("Password1234".toCharArray()));

            Set<Attribute> userAttrs = new HashSet<>();
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_DISPLAY_NAME, username));
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_MAIL_NICKNAME, username));
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_PRINCIPAL_NAME,
                    username + "@" + CONF.getDomain()));
            userAttrs.add(password);
            userAttrs.add(AttributeBuilder.build(PredefinedAttributes.GROUPS_NAME, testGroupUid));
            if (testLicenses()) {
                // add a license
                userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_USAGE_LOCATION, USAGE_LOCATION));
                userAttrs.add(AttributeBuilder.build(AzureAttributes.AZURE_LICENSE_NAME,
                        Collections.singletonList(VALID_LICENSE)));
            }

            created = connector.create(ObjectClass.ACCOUNT, userAttrs, new OperationOptionsBuilder().build());
            assertNotNull(created);

            testUserUid = created.getUidValue();

            // GET USER
            User user = client.getAuthenticated().getUser(testUserUid);
            assertNotNull(user);
            assertEquals(user.getId(), created.getUidValue());
            assertEquals(true, user.getAccountEnabled());
            if (testLicenses()) {
                assertFalse(user.getAssignedLicenses().isEmpty());
                assertEquals(String.valueOf(user.getAssignedLicenses().get(0).getSkuId()), VALID_LICENSE);
                assertEquals(user.getUsageLocation(), USAGE_LOCATION);
            }

            LOG.info("Created User with name {0} on service!", user.getDisplayName());

            // UPDATE USER PASSWORD
            userAttrs.remove(password);
            userAttrs.add(newPassword);
            Uid updated = connector.update(
                    ObjectClass.ACCOUNT, created, userAttrs, new OperationOptionsBuilder().build());
            assertNotNull(updated);

            // GET USER
            user = client.getAuthenticated().getUser(updated.getUidValue());
            assertNotNull(user);
            assertEquals(user.getId(), updated.getUidValue());
            // can't test password update here, Azure API always return '"passwordProfile": null'

            // GET USER GROUPS
            List<Group> groupsForUser = client.getAuthenticated().getAllGroupsForUser(testUserUid);

            assertNotNull(groupsForUser);
            assertEquals(1, groupsForUser.size());
            assertEquals(groupName, groupsForUser.get(0).getDisplayName());

            LOG.info("Added User with name {0} to Group with name : {1}",
                    user.getDisplayName(), group.getDisplayName());

            Thread.sleep(2000);

            // UPDATE GROUP
            groupName = UUID.randomUUID().toString();

            groupAttrs.clear();
            groupAttrs.add(AttributeBuilder.build(AzureAttributes.GROUP_DISPLAY_NAME, groupName));
            groupAttrs.add(AttributeBuilder.build(AzureAttributes.GROUP_ID, testGroupUid));

            updated = connector.update(
                    ObjectClass.GROUP, new Uid(testGroupUid), groupAttrs, new OperationOptionsBuilder().build());
            assertNotNull(updated);
            assertEquals(testGroupUid, updated.getUidValue());
            assertNotEquals(testUserUid, updated.getUidValue());

            testGroupUid = updated.getUidValue();

            LOG.info("Updated Group with old name {0} and new name {1}", group.getDisplayName(), groupName);

            List<Group> userGroups = client.getAuthenticated().getAllGroupsForUser(testUserUid);
            assertNotNull(userGroups);
            assertFalse(userGroups.isEmpty());

            // GET MEMBERS OF
            List<String> memberGroups =
                    client.getAuthenticated().getMemberGroups(testUserUid, false);
            assertNotNull(memberGroups);
            LOG.info("getMemberGroups : {0}", memberGroups);

            List<String> memberObjects =
                    client.getAuthenticated().getMemberObjects(testUserUid, false);
            assertNotNull(memberObjects);
            LOG.info("getMemberObjects : {0}", memberObjects);

            Thread.sleep(2000);

            // UPDATE USER (using 'objectId' attribute)
            username = UUID.randomUUID().toString();
            boolean newStatusValue = false;

            userAttrs.clear();
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_DISPLAY_NAME, username));
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_ID, testUserUid));
            // '__ENABLE__' attribute update
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_ACCOUNT_ENABLED, newStatusValue));
            if (testLicenses()) {
                // licenses update - remove all
                userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_USAGE_LOCATION, USAGE_LOCATION));
                userAttrs.add(AttributeBuilder.build(AzureAttributes.AZURE_LICENSE_NAME, Collections.emptyList()));
            }

            updated = connector.update(
                    ObjectClass.ACCOUNT, new Uid(testUserUid), userAttrs, new OperationOptionsBuilder().build());
            assertNotNull(updated);
            assertEquals(testUserUid, updated.getUidValue());
            assertNotEquals(user.getDisplayName(), username);

            // GET NEW USER (to check 'accountEnabled' update and licenses)
            assertNotEquals(user.getAccountEnabled(), newStatusValue);
            User updatedUser = client.getAuthenticated().getUser(testUserUid);
            assertEquals(updatedUser.getAccountEnabled(), newStatusValue);
            if (testLicenses()) {
                assertTrue(updatedUser.getAssignedLicenses().isEmpty());
                assertEquals(updatedUser.getUsageLocation(), USAGE_LOCATION);
            }

            LOG.info("Updated User with old name {0} and new name {1}", user.getDisplayName(), username);

            // UPDATE USER (using 'userPrincipalName' attribute)
            String anotherUsername = UUID.randomUUID().toString();

            userAttrs.clear();
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_DISPLAY_NAME, anotherUsername));
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_PRINCIPAL_NAME, user.getUserPrincipalName()));

            updated = connector.update(
                    ObjectClass.ACCOUNT, new Uid(testUserUid), userAttrs, new OperationOptionsBuilder().build());
            assertNotNull(updated);
            assertEquals(testUserUid, updated.getUidValue());
            assertNotEquals(updatedUser.getDisplayName(), anotherUsername);

            // GET NEW USER (to check update using 'userPrincipalName' attribute)
            User anotherUpdatedUser = client.getAuthenticated().getUser(testUserUid);
            assertEquals(anotherUpdatedUser.getUserPrincipalName(), user.getUserPrincipalName());

            testUserUid = updated.getUidValue();

            LOG.info("Updated User with old name {0} and new name {1}", user.getDisplayName(), anotherUsername);

            // GET ALL USERS
            List<User> users = client.getAuthenticated().getAllUsers();
            assertNotNull(users);
            assertTrue(!users.isEmpty());

            // GET ALL GROUPS
            List<Group> groups = client.getAuthenticated().getAllGroups();
            assertNotNull(groups);
            assertTrue(!groups.isEmpty());

            // GET GROUP MEMBERS
            // after update group has no members because I did not add user groups to user attributes list
            // see update() function for more info
            List<User> groupMembers = client.getAuthenticated().getAllMembersOfGroup(testGroupUid);
            assertNotNull(groupMembers);
            assertEquals(groupMembers.size(), 0);

            // GET USERS / GROUPS BY NAME
            AzureFilter filter = new AzureFilter(AzureFilterOp.EQUALS,
                    AttributeBuilder.build(AzureAttributes.USER_DISPLAY_NAME, anotherUsername),
                    anotherUsername, false, null);
            List<User> usersFound1 = client.getAuthenticated().getUsersFilteredBy(filter);
            filter = new AzureFilter(AzureFilterOp.EQUALS,
                    AttributeBuilder.build(AzureAttributes.USER_PRINCIPAL_NAME, user.getUserPrincipalName()),
                    user.getUserPrincipalName(), false, null);
            List<User> usersFound2 = client.getAuthenticated().getUsersFilteredBy(filter);
            assertNotNull(usersFound1);
            assertTrue(!usersFound1.isEmpty());
            assertNotNull(usersFound2);
            assertTrue(!usersFound2.isEmpty());

            if (CONF.getRestoreItems()) {
                //DELETE USER
                connector.delete(ObjectClass.ACCOUNT, new Uid(testUserUid), new OperationOptionsBuilder().build());
                try {
                    client.getAuthenticated().getUser(testUserUid);
                    fail(); // must fail
                } catch (RuntimeException e) {
                    assertNotNull(e);
                }

                //CREATE MICROSOFT 365 GROUP
                String group365Name = UUID.randomUUID().toString();

                Set<Attribute> group365Attrs = new HashSet<>();
                group365Attrs.add(AttributeBuilder.build(AzureAttributes.GROUP_DISPLAY_NAME, group365Name));
                group365Attrs.add(AttributeBuilder.build(AzureAttributes.GROUP_MAIL_NICKNAME, group365Name));
                group365Attrs.add(AttributeBuilder.build(AzureAttributes.GROUP_MAIL_ENABLED, true));
                group365Attrs.add(AttributeBuilder.build(AzureAttributes.GROUP_SECURITY_ENABLED, false));
                group365Attrs.add(AttributeBuilder.build("description", "Description test"));
                LinkedList<String> groupTypesList = new LinkedList<>();
                groupTypesList.add("Unified");
                group365Attrs.add(AttributeBuilder.build("groupTypes", groupTypesList));

                Uid createdGroup365 = connector.create(ObjectClass.GROUP, group365Attrs,
                        new OperationOptionsBuilder().build());
                assertNotNull(createdGroup365);

                String testGroup365Uid = createdGroup365.getUidValue();
                Group group365 = client.getAuthenticated().getGroup(testGroup365Uid);
                assertNotNull(group365);

                //DELETE GROUP
                connector.delete(ObjectClass.GROUP, new Uid(testGroup365Uid), new OperationOptionsBuilder().build());
                try {
                    client.getAuthenticated().getGroup(testGroup365Uid);
                    fail(); // must fail
                } catch (RuntimeException e) {
                    assertNotNull(e);
                }

                //RESTORE USER
                Set<Attribute> restoredUserAttrs = new HashSet<>();
                restoredUserAttrs.add(AttributeBuilder.build(AzureAttributes.USER_ID, testUserUid));
                Uid restoredUser = connector.create(ObjectClass.ACCOUNT, restoredUserAttrs,
                        new OperationOptionsBuilder().build());
                assertNotNull(restoredUser);

                //RESTORE GROUP
                Set<Attribute> restoredGroupAttrs = new HashSet<>();
                restoredGroupAttrs.add(AttributeBuilder.build(AzureAttributes.GROUP_ID, testGroup365Uid));
                Uid restoredGroup = connector.create(ObjectClass.GROUP, restoredGroupAttrs,
                        new OperationOptionsBuilder().build());
                assertNotNull(restoredGroup);
            }
        } catch (Exception e) {
            LOG.error(e, "While running test");
            fail(e.getMessage());
        } finally {
            cleanup(connector, client, testUserUid, testGroupUid);
        }
    }

    @Test
    public void pagedSearch() {
        final List<ConnectorObject> results = new ArrayList<>();
        final ResultsHandler handler = new ResultsHandler() {

            @Override
            public boolean handle(final ConnectorObject co) {
                return results.add(co);
            }
        };

        final OperationOptionsBuilder oob = new OperationOptionsBuilder();
        oob.setAttributesToGet("mailNickname");
        oob.setPageSize(2);
        oob.setSortKeys(new SortKey("mailNickname", false));

        CONNECTOR.search(ObjectClass.ACCOUNT, null, handler, oob.build());

        assertEquals(2, results.size());

        results.clear();

        String cookie = "";
        do {
            oob.setPagedResultsCookie(cookie);
            final SearchResult searchResult = CONNECTOR.search(ObjectClass.ACCOUNT, null, handler, oob.build());
            cookie = searchResult.getPagedResultsCookie();
        } while (cookie != null);

        LOG.info("results : {0}", results);

        assertTrue(results.size() > 2);
    }

    @Test
    public void serviceTest() {
        AzureClient client = newClient();

        String testGroup = null;
        String testUser = null;
        UUID uid = UUID.randomUUID();

        try {
            // CREATE USER
            User user = new User();
            user.setAccountEnabled(true);
            user.setDisplayName("TestUser-" + uid.toString());
            user.setMailNickname("testuser-" + uid.toString());
            user.setUserPrincipalName("testuser" + uid.toString().substring(0, 4) + "@" + CONF.getDomain());
            user.setPasswordProfile(AzureUtils.createPassword("Password01"));
            user.setUsageLocation("NL");

            User userCreated = client.getAuthenticated().createUser(user);
            assertNotNull(userCreated);
            assertNotNull(userCreated.getId());
            LOG.info("userCreated : {0}", userCreated);

            // CREATE GROUP
            Group group = new Group();
            group.setDisplayName("TestGroup-" + uid.toString());
            group.setMailNickname("testgroup-" + uid.toString());
            group.setMailEnabled(false);
            group.setSecurityEnabled(true);

            Group groupCreated = client.getAuthenticated().createGroup(group);
            assertNotNull(groupCreated);
            assertNotNull(groupCreated.getId());
            LOG.info("groupCreated : {0}", groupCreated);

            testUser = userCreated.getId();
            testGroup = groupCreated.getId();

            // GET USER
            User userFound = client.getAuthenticated().getUser(testUser);
            assertNotNull(userFound);
            assertNotNull(userFound.getId());
            LOG.info("User found : {0}", userFound);

            // GET GROUP
            Group groupFound = client.getAuthenticated().getGroup(testGroup);
            assertNotNull(groupFound);
            assertNotNull(groupFound.getId());
            LOG.info("Group found : {0}", groupFound);

            // TEST LICENSES
            if (testLicenses()) {
                doTestLicenses(client, testUser);
            }

            // GET ALL
            List<User> users = client.getAuthenticated().getAllUsers();
            assertNotNull(users);
            assertFalse(users.isEmpty());
            LOG.info("Users : {0}", users);

            List<Group> groups = client.getAuthenticated().getAllGroups();
            assertNotNull(groups);
            assertFalse(groups.isEmpty());
            LOG.info("Groups : {0}", groups);

            UserCollectionResponse response = client.getAuthenticated().getAllUsers(1);
            List<User> userList = response.getValue();
            assertNotNull(userList);
            assertFalse(userList.isEmpty());
            assertEquals(1, userList.size());
            LOG.info("Users paged : {0}", userList);

            List<User> userList2 = client.getAuthenticated().
                    getAllUsersNextPage(response.getOdataNextLink()).getValue();
            assertNotNull(userList2);
            assertFalse(userList2.isEmpty());
            assertNotEquals(userList2.get(0).getId(), userList.get(0).getId());
            LOG.info("Users paged 2 : {0}", userList2);

            AzureFilter filter = new AzureFilter(AzureFilterOp.EQUALS,
                    AttributeBuilder.build(AzureAttributes.USER_DISPLAY_NAME, "testuser-" + uid),
                    "testuser-" + uid, false, new ArrayList<>());
            List<User> usersFound = client.getAuthenticated().getUsersFilteredBy(filter);
            assertNotNull(usersFound);
            assertFalse(usersFound.isEmpty());
            LOG.info("User found : {0}", usersFound);

            filter = new AzureFilter(AzureFilterOp.STARTS_WITH,
                    AttributeBuilder.build(AzureAttributes.GROUP_DISPLAY_NAME, "test"),
                    "test", false, new ArrayList<>());
            List<Group> groupsFound = client.getAuthenticated().getGroupsFilteredBy(filter);
            assertNotNull(usersFound);
            assertFalse(usersFound.isEmpty());
            LOG.info("User found : {0}", groupsFound);

            // UPDATE USER
            User newUser = new User();
            newUser.setId(userFound.getId());
            newUser.setCity("City update");
            User userUpdated = client.getAuthenticated().updateUser(newUser);
            assertNotNull(userUpdated);
            assertNotEquals(userUpdated.getCity(), userFound.getCity());
            LOG.info("userUpdated : {0}", userUpdated);

            // UPDATE GROUP
            Group newGroup = new Group();
            newGroup.setId(groupFound.getId());
            newGroup.setDisplayName("Group name update");
            Group groupUpdated = client.getAuthenticated().updateGroup(newGroup);
            assertNotNull(groupUpdated);
            assertNotEquals(groupUpdated.getDisplayName(), groupFound.getDisplayName());
            LOG.info("groupUpdated : {0}", groupUpdated);

            // ADD USER TO GROUP
            client.getAuthenticated().addUserToGroup(testUser, testGroup);
            Boolean memberOf = client.getAuthenticated().isMemberOf(testUser, testGroup);
            assertTrue(memberOf);

            // GET GROUP MEMBERS
            List<User> groupMembers = client.getAuthenticated().getAllMembersOfGroup(testGroup);
            assertNotNull(groupMembers);
            assertFalse(groupMembers.isEmpty());
            LOG.info("Members of Group : {0}", groupMembers);

            // GET USER GROUPS
            List<Group> userGroups = client.getAuthenticated().getAllGroupsForUser(testUser);
            assertNotNull(userGroups);
            assertFalse(userGroups.isEmpty());
            LOG.info("User groups list : {0}", userGroups);

            // GET MEMBERS OF
            List<String> memberGroups =
                    client.getAuthenticated().getMemberGroups(testUser, true);
            assertNotNull(memberGroups);
            LOG.info("getMemberGroups : {0}", memberGroups);

            List<String> memberObjects =
                    client.getAuthenticated().getMemberObjects(testUser, true);
            assertNotNull(memberObjects);
            LOG.info("getMemberObjects : {0}", memberObjects);

            // DELETE USER FROM GROUP
            client.getAuthenticated().deleteUserFromGroup(testUser, testGroup);
            memberOf = client.getAuthenticated().isMemberOf(testUser, testGroup);
            assertFalse(memberOf);

            if (CONF.getRestoreItems()) {
                //DELETE USER
                client.getAuthenticated().deleteUser(testUser);
                try {
                    client.getAuthenticated().getUser(testUser);
                    fail(); // must fail
                } catch (RuntimeException e) {
                    assertNotNull(e);
                }

                //CREATE MICROSOFT 365 GROUP
                Group group365 = new Group();
                group365.setDisplayName("TestGroup-" + uid);
                group365.setMailNickname("testgroup-" + uid);
                group365.setMailEnabled(true);
                group365.setSecurityEnabled(false);
                group365.setGroupTypes(Collections.singletonList("Unified"));

                Group group365Created = client.getAuthenticated().createGroup(group365);
                assertNotNull(group365Created);
                assertNotNull(group365Created.getId());
                LOG.info("groupCreated : {0}", group365Created);

                String testGroup365 = group365Created.getId();

                //DELETE GROUP
                client.getAuthenticated().deleteGroup(testGroup365);
                try {
                    client.getAuthenticated().getGroup(testGroup365);
                    fail(); // must fail
                } catch (RuntimeException e) {
                    assertNotNull(e);
                }

                //RESTORE USER
                DirectoryObject directoryObject = client.getAuthenticated().restoreDirectoryObject(testUser);
                assertNotNull(directoryObject);
                assertNotNull(directoryObject.getId());
                LOG.info("User restored : {0}", directoryObject);
                userFound = client.getAuthenticated().getUser(directoryObject.getId());
                assertNotNull(userFound);

                //RESTORE GROUP
                directoryObject = client.getAuthenticated().restoreDirectoryObject(testGroup365);
                assertNotNull(directoryObject);
                assertNotNull(directoryObject.getId());
                LOG.info("Group restored : {0}", directoryObject);
                groupFound = client.getAuthenticated().getGroup(directoryObject.getId());
                assertNotNull(groupFound);
                assertNotNull(groupFound.getMail());
            }
        } catch (Exception e) {
            LOG.error(e, "While running test");
            fail(e.getMessage());
        } finally {
            cleanup(client, testUser, testGroup);
        }
    }

    private void doTestLicenses(final AzureClient client, final String testUser) {
        // GET SIGNED-IN USER LICENSES
        List<String> licenses = client.getAuthenticated().getCurrentTenantSkuIds(true);
        assertNotNull(licenses);
        LOG.info("Current enabled tenant licenses : {0}", licenses);

        if (licenses.isEmpty()) {
            LOG.info("No licenses for current tenant, skipping licenses test!");
        } else {
            assertTrue(licenses.contains(VALID_LICENSE));

            // ASSIGN LICENSE TO USER
            AssignedLicense assignedLicense = new AssignedLicense();
            assignedLicense.setSkuId(UUID.fromString(VALID_LICENSE));
            AssignLicensePostRequestBody body = new AssignLicensePostRequestBody();
            body.setAddLicenses(Collections.singletonList(assignedLicense));
            LOG.info("New assignedLicense : {0}", assignedLicense);
            client.getAuthenticated().assignLicense(testUser, body);

            User userWithNewLicense = client.getAuthenticated().getUser(testUser);
            assertNotNull(userWithNewLicense);
            assertNotNull(userWithNewLicense.getId());
            assertFalse(userWithNewLicense.getAssignedLicenses().isEmpty());
            assertNotNull(userWithNewLicense.getAssignedLicenses().get(0).getSkuId());
            assertEquals(userWithNewLicense.getAssignedLicenses().get(0).getSkuId(), UUID.fromString(VALID_LICENSE));
            LOG.info("User with new license : {0}", userWithNewLicense);

            // REMOVE LICENSE FROM USER
            body = new AssignLicensePostRequestBody();
            body.setRemoveLicenses(Collections.singletonList(UUID.fromString(VALID_LICENSE)));
            LOG.info("New assignedLicense : {0}", assignedLicense);
            client.getAuthenticated().assignLicense(testUser, body);

            User userWithRemovedLicense = client.getAuthenticated().getUser(testUser);
            assertNotNull(userWithRemovedLicense);
            assertNotNull(userWithRemovedLicense.getId());
            assertTrue(userWithRemovedLicense.getAssignedLicenses().isEmpty());
            LOG.info("User with no more licenses : {0}", userWithRemovedLicense);
        }
    }
}
