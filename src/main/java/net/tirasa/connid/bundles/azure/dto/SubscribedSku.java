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
import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class SubscribedSku {

    @JsonProperty
    private String capabilityStatus;

    @JsonProperty
    private int consumedUnits;

    @JsonProperty
    private String objectId;

    @JsonProperty
    private PrepaidUnit prepaidUnits;

    @JsonProperty
    private List<ServicePlan> servicePlans = new ArrayList<>();

    @JsonProperty
    private String skuId;

    @JsonProperty
    private String skuPartNumber;

    @JsonProperty
    private String appliesTo;

    public String getCapabilityStatus() {
        return capabilityStatus;
    }

    public void setCapabilityStatus(final String capabilityStatus) {
        this.capabilityStatus = capabilityStatus;
    }

    public int getConsumedUnits() {
        return consumedUnits;
    }

    public void setConsumedUnits(final int consumedUnits) {
        this.consumedUnits = consumedUnits;
    }

    public String getObjectId() {
        return objectId;
    }

    public void setObjectId(final String objectId) {
        this.objectId = objectId;
    }

    public PrepaidUnit getPrepaidUnits() {
        return prepaidUnits;
    }

    public void setPrepaidUnits(final PrepaidUnit prepaidUnits) {
        this.prepaidUnits = prepaidUnits;
    }

    public List<ServicePlan> getServicePlans() {
        return servicePlans;
    }

    public void setServicePlans(final List<ServicePlan> servicePlans) {
        this.servicePlans = servicePlans;
    }

    public String getSkuId() {
        return skuId;
    }

    public void setSkuId(final String skuId) {
        this.skuId = skuId;
    }

    public String getSkuPartNumber() {
        return skuPartNumber;
    }

    public void setSkuPartNumber(final String skuPartNumber) {
        this.skuPartNumber = skuPartNumber;
    }

    public String getAppliesTo() {
        return appliesTo;
    }

    public void setAppliesTo(final String appliesTo) {
        this.appliesTo = appliesTo;
    }

    @Override
    public String toString() {
        return "SubscribedSku{" + "capabilityStatus=" + capabilityStatus + ", consumedUnits=" + consumedUnits
                + ", objectId=" + objectId + ", prepaidUnits=" + prepaidUnits + ", servicePlans=" + servicePlans
                + ", skuId=" + skuId + ", skuPartNumber=" + skuPartNumber + ", appliesTo=" + appliesTo + '}';
    }

}
