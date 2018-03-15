package net.tirasa.connid.bundles.azure.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ProvisionedPlan {

    @JsonProperty
    private String capabilityStatus;

    @JsonProperty
    private String provisioningStatus;

    @JsonProperty
    private String service;

    public String getCapabilityStatus() {
        return capabilityStatus;
    }

    public void setCapabilityStatus(final String capabilityStatus) {
        this.capabilityStatus = capabilityStatus;
    }

    public String getProvisioningStatus() {
        return provisioningStatus;
    }

    public void setProvisioningStatus(final String provisioningStatus) {
        this.provisioningStatus = provisioningStatus;
    }

    public String getService() {
        return service;
    }

    public void setService(final String service) {
        this.service = service;
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.toString(this, ToStringStyle.JSON_STYLE);
    }
}
