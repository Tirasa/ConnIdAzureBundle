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
import com.microsoft.graph.http.GraphServiceException;
import com.microsoft.graph.models.AssignedLicense;
import com.microsoft.graph.models.DirectoryObject;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.models.User;
import com.microsoft.graph.models.UserAssignLicenseParameterSet;
import net.tirasa.connid.bundles.azure.service.AzureClient;
import net.tirasa.connid.bundles.azure.utils.AzureAttributes;
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

    private final static Properties PROPS = new Properties();

    private static AzureConnectorConfiguration CONF;

    private static AzureConnector CONN;

    protected static ConnectorFacade connector;

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

        connector = newFacade();

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

        SearchResult result = connector.
                search(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertNotNull(result);
        assertNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());

        assertFalse(handler.getObjects().isEmpty());

        result = connector.
                search(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().setPageSize(1).build());

        assertNotNull(result);
        //assertNotNull(result.getPagedResultsCookie());
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
            } catch (GraphServiceException e) {
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
            } catch (GraphServiceException e) {
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
            assertEquals(group.id, testGroupUid);

            LOG.info("Created Group with name {0} on service!", group.displayName);

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
            assertEquals(user.id, created.getUidValue());
            assertEquals(true, user.accountEnabled);
            if (testLicenses()) {
                assertFalse(user.assignedLicenses.isEmpty());
                assertEquals(String.valueOf(user.assignedLicenses.get(0).skuId), VALID_LICENSE);
                assertEquals(user.usageLocation, USAGE_LOCATION);
            }

            LOG.info("Created User with name {0} on service!", user.displayName);

            // UPDATE USER PASSWORD
            userAttrs.remove(password);
            userAttrs.add(newPassword);
            Uid updated = connector.update(
                    ObjectClass.ACCOUNT, created, userAttrs, new OperationOptionsBuilder().build());
            assertNotNull(updated);

            // GET USER
            user = client.getAuthenticated().getUser(updated.getUidValue());
            assertNotNull(user);
            assertEquals(user.id, updated.getUidValue());
            // can't test password update here, Azure API always return '"passwordProfile": null'

            // GET USER GROUPS
            List<Group> groupsForUser = client.getAuthenticated().getAllGroupsForUser(testUserUid);

            assertNotNull(groupsForUser);
            assertEquals(1, groupsForUser.size());
            assertEquals(groupName, groupsForUser.get(0).displayName);

            LOG.info("Added User with name {0} to Group with name : {1}", user.displayName, group.displayName);

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

            LOG.info("Updated Group with old name {0} and new name {1}", group.displayName, groupName);

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
            assertNotEquals(user.displayName, username);

            // GET NEW USER (to check 'accountEnabled' update and licenses)
            assertNotEquals(user.accountEnabled, newStatusValue);
            User updatedUser = client.getAuthenticated().getUser(testUserUid);
            assertEquals(updatedUser.accountEnabled, newStatusValue);
            if (testLicenses()) {
                assertTrue(updatedUser.assignedLicenses.isEmpty());
                assertEquals(updatedUser.usageLocation, USAGE_LOCATION);
            }

            LOG.info("Updated User with old name {0} and new name {1}", user.displayName, username);

            // UPDATE USER (using 'userPrincipalName' attribute)
            String anotherUsername = UUID.randomUUID().toString();

            userAttrs.clear();
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_DISPLAY_NAME, anotherUsername));
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_PRINCIPAL_NAME, user.userPrincipalName));

            updated = connector.update(
                    ObjectClass.ACCOUNT, new Uid(testUserUid), userAttrs, new OperationOptionsBuilder().build());
            assertNotNull(updated);
            assertEquals(testUserUid, updated.getUidValue());
            assertNotEquals(updatedUser.displayName, anotherUsername);

            // GET NEW USER (to check update using 'userPrincipalName' attribute)
            User anotherUpdatedUser = client.getAuthenticated().getUser(testUserUid);
            assertEquals(anotherUpdatedUser.userPrincipalName, user.userPrincipalName);

            testUserUid = updated.getUidValue();

            LOG.info("Updated User with old name {0} and new name {1}", user.displayName, anotherUsername);

            // GET ALL USERS
            List<User> users = client.getAuthenticated().getAllUsers();
            assertNotNull(users);
            assertTrue(users.size() > 0);

            // GET ALL GROUPS
            List<Group> groups = client.getAuthenticated().getAllGroups();
            assertNotNull(groups);
            assertTrue(groups.size() > 0);

            // GET GROUP MEMBERS
            // after update group has no members because I did not add user groups to user attributes list
            // see update() function for more info
            List<User> groupMembers = client.getAuthenticated().getAllMembersOfGroup(testGroupUid);
            assertNotNull(groupMembers);
            assertEquals(groupMembers.size(), 0);

            // GET USERS / GROUPS BY NAME
            List<User> usersFound1 = client.getAuthenticated().getUsersByName(user.displayName);
            List<User> usersFound2 = client.getAuthenticated().getUsersByName(user.userPrincipalName);
            assertNotNull(usersFound1);
            assertTrue(usersFound1.size() > 0);
            assertNotNull(usersFound2);
            assertTrue(usersFound2.size() > 0);

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

        connector.search(ObjectClass.ACCOUNT, null, handler, oob.build());

        assertEquals(2, results.size());

        results.clear();

        String cookie = "";
        do {
            oob.setPagedResultsCookie(cookie);
            final SearchResult searchResult = connector.search(ObjectClass.ACCOUNT, null, handler, oob.build());
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
            user.accountEnabled = true;
            user.displayName = "TestUser-" + uid.toString();
            user.mailNickname = "testuser-" + uid.toString();
            user.userPrincipalName= "testuser" + uid.toString().substring(0,4) + "@" + CONF.getDomain();
            user.passwordProfile = AzureUtils.createPassword("Password01");
            user.usageLocation = "NL";

            User userCreated = client.getAuthenticated().createUser(user);
            assertNotNull(userCreated);
            assertNotNull(userCreated.id);
            LOG.info("userCreated : {0}", userCreated);

            // CREATE GROUP
            Group group = new Group();
            group.displayName = "TestGroup-" + uid.toString();
            group.mailNickname = "testgroup-" + uid.toString();
            group.mailEnabled = false;
            group.securityEnabled = true;

            Group groupCreated = client.getAuthenticated().createGroup(group);
            assertNotNull(groupCreated);
            assertNotNull(groupCreated.id);
            LOG.info("groupCreated : {0}", groupCreated);

            testUser = userCreated.id;
            testGroup = groupCreated.id;

            // GET USER
            User userFound = client.getAuthenticated().getUser(testUser);
            assertNotNull(userFound);
            assertNotNull(userFound.id);
            LOG.info("User found : {0}", userFound);

            // GET GROUP
            Group groupFound = client.getAuthenticated().getGroup(testGroup);
            assertNotNull(groupFound);
            assertNotNull(groupFound.id);
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

            List<User> userList = client.getAuthenticated().getAllUsers(1);
            assertNotNull(userList);
            assertFalse(userList.isEmpty());
            assertEquals(1, userList.size());
            LOG.info("Users paged : {0}", userList);

            List<User> userList2 = client.getAuthenticated().getAllUsersNextPage(2, "").
                    getNextPage().buildRequest().get().getCurrentPage();
            assertNotNull(userList2);
            assertFalse(userList2.isEmpty());
            assertNotEquals(userList2.get(0).id, userList.get(0).id);
            LOG.info("Users paged 2 : {0}", userList2);

            List<User> usersFound = client.getAuthenticated().getUsersByName("testuser-" + uid.toString());
            assertNotNull(usersFound);
            assertFalse(usersFound.isEmpty());
            LOG.info("User found : {0}", usersFound);

            List<Group> groupsFound = client.getAuthenticated().getGroupsStartsWith("test");
            assertNotNull(usersFound);
            assertFalse(usersFound.isEmpty());
            LOG.info("User found : {0}", groupsFound);

            // UPDATE USER
            User newUser = new User();
            newUser.id = userFound.id;
            newUser.city = "City update";
            User userUpdated = client.getAuthenticated().updateUser(newUser);
            assertNotNull(userUpdated);
            assertNotEquals(userUpdated.city, userFound.city);
            LOG.info("userUpdated : {0}", userUpdated);

            // UPDATE GROUP
            Group newGroup = new Group();
            newGroup.id = groupFound.id;
            newGroup.displayName = "Group name update";
            Group groupUpdated = client.getAuthenticated().updateGroup(newGroup);
            assertNotNull(groupUpdated);
            assertNotEquals(groupUpdated.displayName, groupFound.displayName);
            LOG.info("groupUpdated : {0}", groupUpdated);

            // ADD USER TO GROUP
            client.getAuthenticated().addUserToGroup(testUser, testGroup);
            Boolean memberOf =
                    client.getAuthenticated().isMemberOf(testUser, testGroup);
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
                group365.displayName = "TestGroup-" + uid;
                group365.mailNickname = "testgroup-" + uid;
                group365.mailEnabled = true;
                group365.securityEnabled = false;
                LinkedList<String> groupTypesList = new LinkedList<>();
                groupTypesList.add("Unified");
                group365.groupTypes = groupTypesList;

                Group group365Created = client.getAuthenticated().createGroup(group365);
                assertNotNull(group365Created);
                assertNotNull(group365Created.id);
                LOG.info("groupCreated : {0}", group365Created);

                String testGroup365 = group365Created.id;

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
                assertNotNull(directoryObject.id);
                LOG.info("User restored : {0}", directoryObject);
                userFound = client.getAuthenticated().getUser(directoryObject.id);
                assertNotNull(userFound);

                //RESTORE GROUP
                directoryObject = client.getAuthenticated().restoreDirectoryObject(testGroup365);
                assertNotNull(directoryObject);
                assertNotNull(directoryObject.id);
                LOG.info("Group restored : {0}", directoryObject);
                groupFound = client.getAuthenticated().getGroup(directoryObject.id);
                assertNotNull(groupFound);
                assertNotNull(groupFound.mail);
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
            assignedLicense.skuId = UUID.fromString(VALID_LICENSE);
            UserAssignLicenseParameterSet userAssignLicenseParameterSet = new UserAssignLicenseParameterSet();
            LinkedList<AssignedLicense> assignedLicenses = new LinkedList<>();
            assignedLicenses.add(assignedLicense);
            List<UUID> removedLicenses = new ArrayList<>();
            userAssignLicenseParameterSet.addLicenses = assignedLicenses;
            userAssignLicenseParameterSet.removeLicenses = removedLicenses;
            LOG.info("New assignedLicense : {0}", assignedLicense);
            client.getAuthenticated().assignLicense(testUser, userAssignLicenseParameterSet);

            User userWithNewLicense = client.getAuthenticated().getUser(testUser);
            assertNotNull(userWithNewLicense);
            assertNotNull(userWithNewLicense.id);
            assertFalse(userWithNewLicense.assignedLicenses.isEmpty());
            assertNotNull(userWithNewLicense.assignedLicenses.get(0).skuId);
            assertEquals(userWithNewLicense.assignedLicenses.get(0).skuId, UUID.fromString(VALID_LICENSE));
            LOG.info("User with new license : {0}", userWithNewLicense);

            // REMOVE LICENSE FROM USER
            userAssignLicenseParameterSet = new UserAssignLicenseParameterSet();
            removedLicenses = new ArrayList<>();
            removedLicenses.add(UUID.fromString(VALID_LICENSE));
            assignedLicenses = new LinkedList<>();
            userAssignLicenseParameterSet.removeLicenses = removedLicenses;
            userAssignLicenseParameterSet.addLicenses = assignedLicenses;
            LOG.info("New assignedLicense : {0}", assignedLicense);
            client.getAuthenticated().assignLicense(testUser, userAssignLicenseParameterSet);

            User userWithRemovedLicense = client.getAuthenticated().getUser(testUser);
            assertNotNull(userWithRemovedLicense);
            assertNotNull(userWithRemovedLicense.id);
            assertTrue(userWithRemovedLicense.assignedLicenses.isEmpty());
            LOG.info("User with no more licenses : {0}", userWithRemovedLicense);
        }
    }

}
