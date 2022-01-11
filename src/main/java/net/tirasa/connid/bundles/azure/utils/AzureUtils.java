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

import com.microsoft.graph.models.PasswordProfile;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;

public class AzureUtils {

    private static final Log LOG = Log.getLog(AzureUtils.class);

    public static PasswordProfile createPassword(final String password) {
        PasswordProfile passwordProfile = new PasswordProfile();
        passwordProfile.password = password;
        return passwordProfile;
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
        LOG.error(ex, message);
        throw ConnectorException.wrap(ex);
    }

    public static String getFilter(final AzureFilter filters) {
        switch (filters.getFilterOp()) {
            case EQUALS:
                return filters.getAttribute().getName() + " eq '" + filters.getValue() + "'";
            case STARTS_WITH:
                return "startswith(" + filters.getAttribute().getName() + ",'"  + filters.getValue() + "')";
            case ENDS_WITH:
                return "endswith(" + filters.getAttribute().getName() + ",'" + filters.getValue() + "')";
            case AND:
                return getFilter(filters.getFilters().get(0)) + " and " + getFilter(filters.getFilters().get(1));
            case OR:
                return getFilter(filters.getFilters().get(0)) + " or " + getFilter(filters.getFilters().get(1));
            default:
                throw new ConnectorException("Invalid search filter");
        }
    }
}
