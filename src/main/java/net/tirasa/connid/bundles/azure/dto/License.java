/**
 * Copyright (C) 2016 ConnId (connid-dev@googlegroups.com)
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
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class License {

    private List<Assigned> addLicenses = new ArrayList<>();

    private List<String> removeLicenses = new ArrayList<>();

    public static class Assigned {

        private List<String> disabledPlans = new ArrayList<>();

        private String skuId;

        @JsonProperty("disabledPlans")
        public List<String> getDisabledPlans() {
            return disabledPlans;
        }

        public void setDisabledPlans(final List<String> disabledPlans) {
            this.disabledPlans = disabledPlans;
        }

        @JsonProperty("skuId")
        public String getSkuId() {
            return skuId;
        }

        public void setSkuId(final String skuId) {
            this.skuId = skuId;
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            Assigned assigned = (Assigned) o;
            return skuId.equals(assigned.skuId);

        }

        @Override
        public int hashCode() {
            return skuId.hashCode();
        }

        @Override
        public String toString() {
            return ReflectionToStringBuilder.toString(this, ToStringStyle.JSON_STYLE);
        }
    }

    public static License create(final License license) {
        License result = license;
        if (license == null) {
            result = new License();
            result.setAddLicenses(new ArrayList<License.Assigned>());
            result.setRemoveLicenses(new ArrayList<String>());
        }
        return result;
    }

    public static License create(final List<String> skuIds, final boolean add) {
        License result = new License();

        if (add) {
            ArrayList<Assigned> toAdd = new ArrayList<>();
            for (String skuId : skuIds) {
                License.Assigned assigned = new License.Assigned();
                assigned.setSkuId(skuId);
                toAdd.add(assigned);
            }
            result.setAddLicenses(toAdd);
        } else {
            result.setRemoveLicenses(skuIds);
        }

        return result;
    }

    @JsonProperty("addLicenses")
    public List<Assigned> getAddLicenses() {
        return addLicenses;
    }

    public void setAddLicenses(final List<Assigned> addLicenses) {
        this.addLicenses = addLicenses;
    }

    @JsonProperty("removeLicenses")
    public List<String> getRemoveLicenses() {
        return removeLicenses;
    }

    public void setRemoveLicenses(final List<String> removeLicenses) {
        this.removeLicenses = removeLicenses;
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.toString(this, ToStringStyle.JSON_STYLE);
    }

}
