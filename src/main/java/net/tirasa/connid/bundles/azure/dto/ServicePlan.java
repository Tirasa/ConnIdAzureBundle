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
package net.tirasa.connid.bundles.azure.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ServicePlan {

    @JsonProperty
    private String servicePlanId;

    @JsonProperty
    private String servicePlanName;

    @JsonProperty
    private String provisioningStatus;

    @JsonProperty
    private String appliesTo;

    public String getServicePlanId() {
        return servicePlanId;
    }

    public void setServicePlanId(final String servicePlanId) {
        this.servicePlanId = servicePlanId;
    }

    public String getServicePlanName() {
        return servicePlanName;
    }

    public void setServicePlanName(final String servicePlanName) {
        this.servicePlanName = servicePlanName;
    }

    public String getProvisioningStatus() {
        return provisioningStatus;
    }

    public void setProvisioningStatus(final String provisioningStatus) {
        this.provisioningStatus = provisioningStatus;
    }

    public String getAppliesTo() {
        return appliesTo;
    }

    public void setAppliesTo(final String appliesTo) {
        this.appliesTo = appliesTo;
    }

    @Override
    public String toString() {
        return "ServicePlan{" + "servicePlanId=" + servicePlanId + ", servicePlanName=" + servicePlanName
                + ", provisioningStatus=" + provisioningStatus + ", appliesTo=" + appliesTo + '}';
    }

}
