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
package net.tirasa.connid.bundles.azure.utils;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;

public class AzureUtils {

    private static final Log LOG = Log.getLog(AzureUtils.class);

    public final static ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public static Object extractCorrectValue(final JsonNode node) {
        return StringUtil.isNotBlank(node.textValue())
                ? node.textValue()
                : (node.asText().equals("false") || node.asText().equals("true") ? node.asBoolean() : node.asText());
    }

    public static GuardedString createPassword(final String password) {
        GuardedString guardedString = new GuardedString(password.toCharArray());
        return guardedString;
    }

    public static String getPasswordValue(final GuardedString guardedString) {
        final StringBuilder clearPwd = new StringBuilder();
        GuardedString.Accessor accessor =
                new GuardedString.Accessor() {

            @Override
            public void access(final char[] clearChars) {
                clearPwd.append(clearChars);
            }
        };
        guardedString.access(accessor);
        return clearPwd.toString();
    }

    public static void handleGeneralError(final String message) {
        LOG.error("General error : {0}", message);
        throw new ConnectorException(message);
    }

    public static void handleGeneralError(final String message, final Exception ex) {
        LOG.error(ex, message);
        throw new ConnectorException(message, ex);
    }

    public static void wrapGeneralError(final String message, final Exception ex) {
        String newMessage = message + " - "
                + ex.getMessage() != null ? ex.getMessage() : "";
        LOG.error(ex, newMessage);
        throw ConnectorException.wrap(ex);
    }

    public static boolean checkAttribute(final String attributeName, final Map<String, List<Attribute>> attributes) {
        return attributes.containsKey(attributeName)
                && attributes.get(attributeName) != null
                && !attributes.get(attributeName).isEmpty();
    }
}
