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

import java.util.List;
import org.identityconnectors.framework.common.objects.Attribute;

public class AzureFilter {

    private final AzureFilterOp filterOp;

    private final Attribute attribute;

    private final Object value;

    private final boolean quote;

    private final List<AzureFilter> filters;

    public AzureFilter(final AzureFilterOp filterOp,
            final Attribute attribute,
            final Object value,
            final boolean quote,
            final List<AzureFilter> filters) {
        this.filterOp = filterOp;
        this.attribute = attribute;
        this.value = value;
        this.quote = quote;
        this.filters = filters;
    }

    public AzureFilterOp getFilterOp() {
        return filterOp;
    }

    public Attribute getAttribute() {
        return attribute;
    }

    public Object getValue() {
        return value;
    }

    public boolean isQuote() {
        return quote;
    }

    public List<AzureFilter> getFilters() {
        return filters;
    }

    @Override
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        toString(builder);
        return builder.toString();
    }

    public void toString(final StringBuilder builder) {
        switch (filterOp) {
            case AND:
            case OR:
                for (int i = 0; i < filters.size(); i++) {
                    if (i != 0) {
                        builder.append(' ');
                        builder.append(filterOp);
                        builder.append(' ');
                    }

                    builder.append(filters.get(i));
                }
                break;

            case EQUALS:
            case CONTAINS:
            case STARTS_WITH:
            case GREATER_THAN:
            case GREATER_OR_EQUAL:
            case LESS_THAN:
            case LESS_OR_EQUAL:
                builder.append(attribute);
                builder.append(' ');
                builder.append(filterOp);
                builder.append(' ');

                if (quote) {
                    builder.append("\"");
                    builder.append(value);
                    builder.append("\"");
                } else {
                    builder.append(value);
                }
                break;

            case IS_PRESENT:
                builder.append(attribute);
                builder.append(' ');
                builder.append(filterOp);
                break;

            default:
        }
    }
}
