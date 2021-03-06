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
package net.tirasa.connid.bundles.azure.dto;

import java.util.Collections;
import java.util.List;
import org.identityconnectors.common.StringUtil;

public class PagedGroups implements AzurePagedObject {

    private List<Group> groups;

    private String skipToken;

    public List<Group> getGroups() {
        return Collections.unmodifiableList(groups);
    }

    public void setGroups(List<Group> user) {
        this.groups = user;
    }

    @Override
    public String getSkipToken() {
        return skipToken;
    }

    @Override
    public void setSkipToken(String skipToken) {
        this.skipToken = skipToken;
    }

    public Boolean hasMoreResults() {
        return StringUtil.isNotBlank(getSkipToken());
    }
}
