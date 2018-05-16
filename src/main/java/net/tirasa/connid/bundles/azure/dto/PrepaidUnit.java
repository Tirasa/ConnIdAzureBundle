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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class PrepaidUnit {

    @JsonProperty
    private int enabled;

    @JsonProperty
    private int suspended;

    @JsonProperty
    private int warning;

    public int getEnabled() {
        return enabled;
    }

    public void setEnabled(final int enabled) {
        this.enabled = enabled;
    }

    public int getSuspended() {
        return suspended;
    }

    public void setSuspended(final int suspended) {
        this.suspended = suspended;
    }

    public int getWarning() {
        return warning;
    }

    public void setWarning(final int warning) {
        this.warning = warning;
    }

    @Override
    public String toString() {
        return "PrepaidUnit{" + "enabled=" + enabled + ", suspended=" + suspended + ", warning=" + warning + '}';
    }

}
