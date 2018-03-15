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

    @Override
    public String toString() {
        return ReflectionToStringBuilder.toString(this, ToStringStyle.JSON_STYLE);
    }
}
