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
package net.tirasa.connid.bundles.azure.utils;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.tirasa.connid.bundles.azure.AzureConnector;
import net.tirasa.connid.bundles.azure.dto.AzureObject;
import net.tirasa.connid.bundles.azure.service.AzureService;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;

public final class AzureAttributes {

    public static final String USER_ID = "objectId";

    public static final String USER_DISPLAY_NAME = "displayName";

    public static final String USER_PRINCIPAL_NAME = "userPrincipalName";

    public static final String USER_ACCOUNT_ENABLED = "accountEnabled";

    public static final String USER_PASSWORD = "passwordProfile";

    public static final String USER_PASSWORD_PROFILE = "passwordProfile";

    public static final String USER_MAIL_NICKNAME = "mailNickname";

    public static final String GROUP_ID = "objectId";

    public static final String GROUP_DISPLAY_NAME = "displayName";

    public static final String GROUP_MAIL_ENABLED = "mailEnabled";

    public static final String GROUP_MAIL_NICKNAME = "mailNickname";

    public static final String GROUP_SECURITY_ENABLED = "securityEnabled";

    public static final String AZURE_LICENSE_NAME = "azureLicense";

    public static final String USER_USAGE_LOCATION = "usageLocation";

    public static final String SUBSCRIBED_SKU_ID = "objectId";

    public static final List<String> GROUP_REQUIRED_ATTRS = new ArrayList<String>() {

        private static final long serialVersionUID = 3109256773218160485L;

        {
            add(GROUP_DISPLAY_NAME);
            add(GROUP_MAIL_ENABLED);
            add(GROUP_MAIL_NICKNAME);
            add(GROUP_SECURITY_ENABLED);
        }
    };

    public static final List<String> USER_REQUIRED_ATTRS = new ArrayList<String>() {

        private static final long serialVersionUID = 3109256773218160485L;

        {
            add(USER_ACCOUNT_ENABLED);
            add(USER_DISPLAY_NAME);
            // required only if you using a federated domain for the user's userPrincipalName (UPN) property.
//            add("immutableId");
            add(USER_MAIL_NICKNAME);
            add(USER_PASSWORD_PROFILE);
            add(USER_PRINCIPAL_NAME);
        }
    };

    public static Schema buildSchema() {

        SchemaBuilder builder = new SchemaBuilder(AzureConnector.class);

        List<Map<String, String>> userMetadata = AzureService.getMetadata(AzureService.USER_METADATA_TYPE_ID_VALUE);
        List<Map<String, String>> groupMetadata = AzureService.getMetadata(AzureService.GROUP_METADATA_TYPE_ID_VALUE);

        ObjectClassInfoBuilder userBuilder = new ObjectClassInfoBuilder().setType(ObjectClass.ACCOUNT_NAME);
        ObjectClassInfo user;
        userBuilder.addAttributeInfo(Name.INFO);
        for (Map<String, String> userMetadataElem : userMetadata) {
            String name = userMetadataElem.get(AzureService.METADATA_NAME_ID);
            String type = userMetadataElem.get(AzureService.METADATA_TYPE_ID);

            userBuilder.addAttributeInfo(AttributeInfoBuilder.define(name)
                    .setRequired(USER_REQUIRED_ATTRS.contains(name))
                    .setType(getCorrectType(type))
                    .setMultiValued(StringUtil.isNotBlank(type)
                            && type.contains(AzureService.METADATA_COLLECTION_VALUE)).build());
        }

        user = userBuilder.build();
        builder.defineObjectClass(user);

        ObjectClassInfoBuilder groupBuilder = new ObjectClassInfoBuilder().setType(ObjectClass.GROUP_NAME);
        ObjectClassInfo group;
        groupBuilder.addAttributeInfo(Name.INFO);
        for (Map<String, String> groupMetadataElem : groupMetadata) {
            String name = groupMetadataElem.get(AzureService.METADATA_NAME_ID);
            String type = groupMetadataElem.get(AzureService.METADATA_TYPE_ID);

            groupBuilder.addAttributeInfo(AttributeInfoBuilder.define(name)
                    .setRequired(GROUP_REQUIRED_ATTRS.contains(name))
                    .setType(getCorrectType(type))
                    .setMultiValued(StringUtil.isNotBlank(type)
                            && type.contains(AzureService.METADATA_COLLECTION_VALUE)).build());
        }
        group = groupBuilder.build();
        builder.defineObjectClass(group);

        return builder.build();
    }

    public static Class<?> getCorrectType(String type) {
        if (StringUtil.isBlank(type)) {
            return String.class;
        }
        Class<?> typeClass = String.class; // default
        switch (type) {
            case "String":
                typeClass = String.class;
                break;
            case "Boolean":
                typeClass = Boolean.class;
                break;
            case "Stream":
                typeClass = byte[].class;
                break;
            default:
                break;
        }
        return typeClass;
    }

    public static AttributeBuilder buildAttributeFromClassField(final Field field,
            final AzureObject that) throws IllegalArgumentException, IllegalAccessException {
        return doBuildAttributeFromClassField(field.get(that), USER_ID, field.getType());
    }

    public static AttributeBuilder doBuildAttributeFromClassField(final Object value,
            final String name,
            final Class<?> clazz) {
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        if (value != null) {
            if (clazz == boolean.class || clazz == Boolean.class) {
                attributeBuilder.addValue(Boolean.class.cast(value));
            } else if (value instanceof List<?>) {
                ArrayList<?> list = new ArrayList<>((List<?>) value);
                if (list.size() > 1) {
                    for (Object elem : list) {
                        doBuildAttributeFromClassField(elem, name, clazz);
                    }
                } else if (!list.isEmpty()) {
                    attributeBuilder.addValue(list.get(0).toString());
                }
            } else {
                attributeBuilder.addValue(value.toString());
            }
        }
        if (name != null) {
            attributeBuilder.setName(name);
        }
        return attributeBuilder;
    }

}
