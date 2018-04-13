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
public class License {

    private List<AssignedLicense> addLicenses = new ArrayList<>();

    private List<String> removeLicenses = new ArrayList<>();

    @JsonProperty("addLicenses")
    public List<AssignedLicense> getAddLicenses() {
        return addLicenses;
    }

    public void setAddLicenses(final List<AssignedLicense> addLicenses) {
        this.addLicenses = addLicenses;
    }

    @JsonProperty("removeLicenses")
    public List<String> getRemoveLicenses() {
        return removeLicenses;
    }

    public void setRemoveLicenses(final List<String> removeLicenses) {
        this.removeLicenses = removeLicenses;
    }

    public static License create(final License license) {
        License result = license;
        if (license == null) {
            result = new License();
            result.setAddLicenses(new ArrayList<AssignedLicense>());
            result.setRemoveLicenses(new ArrayList<String>());
        }
        return result;
    }

    public static License create(final List<String> skuIds, final boolean add) {
        License result = new License();

        if (add) {
            ArrayList<AssignedLicense> toAdd = new ArrayList<>();
            for (String skuId : skuIds) {
                AssignedLicense assigned = new AssignedLicense();
                assigned.setSkuId(skuId);
                toAdd.add(assigned);
            }
            result.setAddLicenses(toAdd);
        } else {
            result.setRemoveLicenses(skuIds);
        }

        return result;
    }

}
