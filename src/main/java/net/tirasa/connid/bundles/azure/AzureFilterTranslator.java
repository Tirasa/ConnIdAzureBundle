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

import net.tirasa.connid.bundles.azure.utils.AzureAttributes;
import net.tirasa.connid.bundles.azure.utils.AzureFilter;
import net.tirasa.connid.bundles.azure.utils.AzureFilterOp;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.AttributeFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EndsWithFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsIgnoreCaseFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.StartsWithFilter;
import java.util.Arrays;
import java.util.List;

public class AzureFilterTranslator extends AbstractFilterTranslator<AzureFilter> {

    private static final Log LOG = Log.getLog(AzureFilterTranslator.class);

    private final ObjectClass objectClass;

    public AzureFilterTranslator(final ObjectClass objectClass) {
        this.objectClass = objectClass;
    }

    @Override
    public AzureFilter createAndExpression(final AzureFilter leftExpression, final AzureFilter rightExpression) {
        return createAzureFilter(AzureFilterOp.AND, null, false, Arrays.asList(leftExpression, rightExpression), false);
    }

    @Override
    public AzureFilter createOrExpression(final AzureFilter leftExpression, final AzureFilter rightExpression) {
        return createAzureFilter(AzureFilterOp.OR, null, false, Arrays.asList(leftExpression, rightExpression), false);
    }

    @Override
    public AzureFilter createContainsExpression(final ContainsFilter filter, final boolean not) {
        return createAzureFilter(AzureFilterOp.CONTAINS, filter, true, null, not);
    }

    @Override
    public AzureFilter createEndsWithExpression(final EndsWithFilter filter, final boolean not) {
        return createAzureFilter(AzureFilterOp.ENDS_WITH, filter, true, null, not);
    }

    @Override
    public AzureFilter createStartsWithExpression(final StartsWithFilter filter, final boolean not) {
        return createAzureFilter(AzureFilterOp.STARTS_WITH, filter, true, null, not);
    }

    @Override
    public AzureFilter createGreaterThanExpression(final GreaterThanFilter filter, final boolean not) {
        return createAzureFilter(AzureFilterOp.GREATER_THAN, filter, true, null, not);
    }

    @Override
    public AzureFilter createGreaterThanOrEqualExpression(final GreaterThanOrEqualFilter filter, final boolean not) {
        return createAzureFilter(AzureFilterOp.GREATER_OR_EQUAL, filter, true, null, not);
    }

    @Override
    public AzureFilter createLessThanExpression(final LessThanFilter filter, final boolean not) {
        return createAzureFilter(AzureFilterOp.LESS_THAN, filter, true, null, not);
    }

    @Override
    public AzureFilter createLessThanOrEqualExpression(final LessThanOrEqualFilter filter, final boolean not) {
        return createAzureFilter(AzureFilterOp.LESS_OR_EQUAL, filter, true, null, not);
    }

    @Override
    public AzureFilter createEqualsExpression(final EqualsFilter filter, final boolean not) {
        return createAzureFilter(AzureFilterOp.EQUALS, filter, true, null, not);
    }

    @Override
    public AzureFilter createEqualsIgnoreCaseExpression(final EqualsIgnoreCaseFilter filter, final boolean not) {
        return createAzureFilter(AzureFilterOp.EQUALS, filter, true, null, not);
    }

    private AzureFilter createAzureFilter(final AzureFilterOp type, final AttributeFilter filter,
                                          final boolean quote, final List<AzureFilter> filters, final boolean not) {
        checkIfNot(not);
        return filter == null
                ? new AzureFilter(type, null, null, quote, filters)
                : new AzureFilter(type, filter.getAttribute(), getFilterValue(filter), quote, filters);
    }

    private String getFilterName(final AttributeFilter filter) {
        if (ObjectClass.GROUP == objectClass) {
            return AzureAttributes.GROUP_ID.equals(filter.getName()) || Name.NAME.equals(filter.getName())
                    ? filter.getName() : "profile." + filter.getName();
        } else {
            return AzureAttributes.USER_ID.equals(filter.getName()) ? filter.getName() : "profile." + filter.getName();
        }
    }

    private String getFilterValue(final AttributeFilter filter) {
        Object attrValue = AttributeUtil.getSingleValue(filter.getAttribute());
        if (attrValue == null) {
            return null;
        }
        return attrValue.toString();
    }

    private void checkIfNot(final boolean not) {
        if (not) {
            LOG.info("Search with not is not supported by Okta");
        }
    }
}
