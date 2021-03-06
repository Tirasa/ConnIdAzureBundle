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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import net.tirasa.connid.bundles.azure.dto.AvailableExtensionProperties;
import net.tirasa.connid.bundles.azure.dto.Group;
import net.tirasa.connid.bundles.azure.dto.License;
import net.tirasa.connid.bundles.azure.dto.PagedUsers;
import net.tirasa.connid.bundles.azure.dto.User;
import net.tirasa.connid.bundles.azure.service.AzureClient;
import net.tirasa.connid.bundles.azure.service.NoSuchEntityException;
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
import org.junit.BeforeClass;
import org.junit.Test;

public class AzureConnectorTests {

    private static final Log LOG = Log.getLog(AzureConnectorTests.class);

    private final static Properties PROPS = new Properties();

    private static AzureConnectorConfiguration CONF;

    private static AzureConnector CONN;

    protected static ConnectorFacade connector;

    private static String VALID_LICENSE;

    private static String USAGE_LOCATION;

    @BeforeClass
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
            } catch (NoSuchEntityException e) {
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
            } catch (NoSuchEntityException e) {
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
            groupAttrs.add(AttributeBuilder.build(AzureAttributes.GROUP_SECURITY_ENABLED, true));
            groupAttrs.add(AttributeBuilder.build("description", "Description test"));

            Uid created = connector.create(ObjectClass.GROUP, groupAttrs, new OperationOptionsBuilder().build());
            assertNotNull(created);

            testGroupUid = created.getUidValue();

            // GET GROUP
            Group group = client.getAuthenticated().getGroup(testGroupUid);
            assertNotNull(group);
            assertEquals(group.getObjectId(), testGroupUid);

            LOG.info("Created Group with name {0} on service!",
                    group.getDisplayName());

            // CREATE USER
            String username = UUID.randomUUID().toString();
            Attribute password = AttributeBuilder.buildPassword(new GuardedString("Password123".toCharArray()));
            Attribute newPassword = AttributeBuilder.buildPassword(new GuardedString("Password1234".toCharArray()));

            Set<Attribute> userAttrs = new HashSet<>();
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_DISPLAY_NAME, username));
            userAttrs.add(AttributeBuilder.build(AzureAttributes.USER_MAIL_NICKNAME, username));
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
            assertEquals(user.getObjectId(), created.getUidValue());
            assertEquals(user.getAccountEnabled(), true);
            if (testLicenses()) {
                assertFalse(user.getAssignedLicenses().isEmpty());
                assertEquals(user.getAssignedLicenses().get(0).getSkuId(), VALID_LICENSE);
                assertEquals(user.getUsageLocation(), USAGE_LOCATION);
            }

            LOG.info("Created User with name {0} on service!",
                    user.getDisplayName());

            // UPDATE USER PASSWORD
            userAttrs.remove(password);
            userAttrs.add(newPassword);
            Uid updated = connector.update(
                    ObjectClass.ACCOUNT, created, userAttrs, new OperationOptionsBuilder().build());
            assertNotNull(updated);

            // GET USER
            user = client.getAuthenticated().getUser(updated.getUidValue());
            assertNotNull(user);
            assertEquals(user.getObjectId(), updated.getUidValue());
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

            LOG.info("Updated Group with old name {0} and new name {1}",
                    group.getDisplayName(), groupName);

            List<Group> userGroups = client.getAuthenticated().getAllGroupsForUser(testUserUid);
            assertNotNull(userGroups);
            assertFalse(userGroups.isEmpty());

            // GET MEMBERS OF
            List<String> memberGroups =
                    client.getAuthenticated().getMemberGroups("users", testUserUid, false);
            assertNotNull(memberGroups);
            LOG.info("getMemberGroups : {0}", memberGroups);

            List<String> memberObjects =
                    client.getAuthenticated().getMemberObjects("users", testUserUid, false);
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

            LOG.info("Updated User with old name {0} and new name {1}",
                    user.getDisplayName(), username);

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

            LOG.info("Updated User with old name {0} and new name {1}",
                    user.getDisplayName(), anotherUsername);

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
            List<User> usersFound1 = client.getAuthenticated().getUsersByName(user.getDisplayName());
            List<User> usersFound2 = client.getAuthenticated().getUsersByName(user.getMailNickname());
            assertNotNull(usersFound1);
            assertTrue(usersFound1.size() > 0);
            assertNotNull(usersFound2);
            assertTrue(usersFound2.size() > 0);

            // TEST USER / GROUP "to attributes" CONVERSION
            LOG.info("User to Attributes: {0}", user.toAttributes());
            LOG.info("Group to Attributes: {0}", group.toAttributes());
        } catch (Exception e) {
            LOG.error(e, "While running test");
            fail(e.getMessage());
        } finally {
            cleanup(connector, client, testUserUid, testGroupUid);
        }
    }

    @Test
    public void pagedSearch() {
        final List<ConnectorObject> results = new ArrayList<ConnectorObject>();
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
            user.setAccountEnabled(true);
            user.setDisplayName("TestUser-" + uid.toString());
            user.setMailNickname("testuser-" + uid.toString());
//            user.setUserPrincipalName("testuser@" + CONF.getDomain()); // will be [mailNickname@AZURE_DOMAIN]
            user.setPassword(AzureUtils.createPassword("Password01"));
            user.setUsageLocation("NL");

            User userCreated = client.getAuthenticated().createUser(user);
            assertNotNull(userCreated);
            assertNotNull(userCreated.getObjectId());
            LOG.info("userCreated : {0}", userCreated);

            // CREATE GROUP
            Group group = new Group();
            group.setDisplayName("TestGroup-" + uid.toString());
            group.setMailNickname("testgroup-" + uid.toString());
            group.setSecurityEnabled(true);

            Group groupCreated = client.getAuthenticated().createGroup(group);
            assertNotNull(groupCreated);
            assertNotNull(groupCreated.getObjectId());
            LOG.info("groupCreated : {0}", groupCreated);

            testUser = userCreated.getObjectId();
            testGroup = groupCreated.getObjectId();

            // GET USER
            User userFound = client.getAuthenticated().getUser(testUser);
            assertNotNull(userFound);
            assertNotNull(userFound.getObjectId());
            LOG.info("User found : {0}", userFound);

            // USER TO ATTRIBUTES
            LOG.info("Attributes user : {0}", userFound.toAttributes());

            // GET GROUP
            Group groupFound = client.getAuthenticated().getGroup(testGroup);
            assertNotNull(groupFound);
            assertNotNull(groupFound.getObjectId());
            LOG.info("Group found : {0}", groupFound);

            // GROUP TO ATTRIBUTES
            LOG.info("Attributes group : {0}", groupFound.toAttributes());

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

            PagedUsers usersPaged = client.getAuthenticated().getAllUsers(1);
            assertNotNull(usersPaged);
            assertFalse(usersPaged.getUsers().isEmpty());
            assertTrue(usersPaged.getUsers().size() == 1);
            assertNotNull(usersPaged.getSkipToken());
            LOG.info("Users paged : {0}", usersPaged);

            PagedUsers usersPaged2 =
                    client.getAuthenticated().getAllUsersNextPage(2, usersPaged.getSkipToken(), false);
            assertNotNull(usersPaged2);
            assertFalse(usersPaged2.getUsers().isEmpty());
            assertFalse(usersPaged2.getUsers().get(0).getObjectId().equals(usersPaged.getUsers().get(0).getObjectId()));
            LOG.info("Users paged 2 : {0}", usersPaged2);

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
            newUser.setObjectId(userFound.getObjectId());
            newUser.setCity("City update");
            User userUpdated = client.getAuthenticated().updateUser(newUser);
            assertNotNull(userUpdated);
            assertFalse(userUpdated.getCity().equals(userFound.getCity()));
            LOG.info("userUpdated : {0}", userUpdated);

            // UPDATE GROUP
            Group newGroup = new Group();
            newGroup.setObjectId(groupFound.getObjectId());
            newGroup.setDisplayName("Group name update");
            Group groupUpdated = client.getAuthenticated().updateGroup(newGroup);
            assertNotNull(groupUpdated);
            assertFalse(groupUpdated.getDisplayName().equals(groupFound.getDisplayName()));
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
                    client.getAuthenticated().getMemberGroups("users", testUser, false);
            assertNotNull(memberGroups);
            LOG.info("getMemberGroups : {0}", memberGroups);

            List<String> memberObjects =
                    client.getAuthenticated().getMemberObjects("users", testUser, false);
            assertNotNull(memberObjects);
            LOG.info("getMemberObjects : {0}", memberObjects);

            // DELETE USER FROM GROUP
            client.getAuthenticated().deleteUserFromGroup(testUser, testGroup);
            memberOf =
                    client.getAuthenticated().isMemberOf(testUser, testGroup);
            assertFalse(memberOf);

            // AVAILABLE EXTENSION PROPERTIES
            AvailableExtensionProperties availableProperties =
                    client.getAuthenticated().getAvailableExtensionProperties(testUser, false);
            assertNotNull(availableProperties);
            LOG.info("availableProperties : {0}", availableProperties);
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
            License assignedLicense = License.create(Arrays.asList(VALID_LICENSE), true);
            LOG.info("New assignedLicense : {0}", assignedLicense);
            client.getAuthenticated().assignLicense(testUser, assignedLicense);

            User userWithNewLicense = client.getAuthenticated().getUser(testUser);
            assertNotNull(userWithNewLicense);
            assertNotNull(userWithNewLicense.getObjectId());
            assertFalse(userWithNewLicense.getAssignedLicenses().isEmpty());
            assertNotNull(userWithNewLicense.getAssignedLicenses().get(0).getSkuId());
            assertTrue(userWithNewLicense.getAssignedLicenses().get(0).getSkuId().equals(VALID_LICENSE));
            LOG.info("User with new license : {0}", userWithNewLicense);

            // REMOVE LICENSE FROM USER
            assignedLicense = License.create(Arrays.asList(VALID_LICENSE), false);
            LOG.info("New assignedLicense : {0}", assignedLicense);
            client.getAuthenticated().assignLicense(testUser, assignedLicense);

            User userWithRemovedLicense = client.getAuthenticated().getUser(testUser);
            assertNotNull(userWithRemovedLicense);
            assertNotNull(userWithRemovedLicense.getObjectId());
            assertTrue(userWithRemovedLicense.getAssignedLicenses().isEmpty());
            LOG.info("User with no more licenses : {0}", userWithRemovedLicense);
        }
    }

}
