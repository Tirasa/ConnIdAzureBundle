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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class AvailableExtensionProperties {

    private String odata_type;

    @JsonProperty
    private String objectType;

    @JsonProperty
    private String objectId;

    @JsonProperty
    private String deletionTimestamp;

    @JsonProperty
    private String appDisplayName;

    @JsonProperty
    private String name;

    @JsonProperty
    private String dataType;

    @JsonProperty
    private String isSyncedFromOnPremises;

    @JsonProperty
    private List<String> targetObjects = new ArrayList<>();

    @JsonProperty("odata.type")
    public String getOdata_type() {
        return odata_type;
    }

    public void setOdata_type(String odata_type) {
        this.odata_type = odata_type;
    }

    public String getObjectType() {
        return objectType;
    }

    public void setObjectType(String objectType) {
        this.objectType = objectType;
    }

    public String getObjectId() {
        return objectId;
    }

    public void setObjectId(String objectId) {
        this.objectId = objectId;
    }

    public String getDeletionTimestamp() {
        return deletionTimestamp;
    }

    public void setDeletionTimestamp(String deletionTimestamp) {
        this.deletionTimestamp = deletionTimestamp;
    }

    public String getAppDisplayName() {
        return appDisplayName;
    }

    public void setAppDisplayName(String appDisplayName) {
        this.appDisplayName = appDisplayName;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDataType() {
        return dataType;
    }

    public void setDataType(String dataType) {
        this.dataType = dataType;
    }

    public String getIsSyncedFromOnPremises() {
        return isSyncedFromOnPremises;
    }

    public void setIsSyncedFromOnPremises(String isSyncedFromOnPremises) {
        this.isSyncedFromOnPremises = isSyncedFromOnPremises;
    }

    public List<String> getTargetObjects() {
        return targetObjects;
    }

    public void setTargetObjects(List<String> targetObjects) {
        this.targetObjects = targetObjects;
    }
}
