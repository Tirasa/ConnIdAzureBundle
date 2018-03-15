package net.tirasa.connid.bundles.azure.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Date;
import java.util.UUID;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AssignedPlan {

    private Date assignedTimestamp;

    private String capabilityStatus;

    private String service;

    private UUID servicePlanId;

    @JsonProperty("assignedTimestamp")
    public Date getAssignedTimestamp() {
        return assignedTimestamp;
    }

    public void setAssignedTimestamp(Date assignedTimestamp) {
        this.assignedTimestamp = assignedTimestamp;
    }

    @JsonProperty("capabilityStatus")
    public String getCapabilityStatus() {
        return capabilityStatus;
    }

    public void setCapabilityStatus(String capabilityStatus) {
        this.capabilityStatus = capabilityStatus;
    }

    @JsonProperty("service")
    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    @JsonProperty("servicePlanId")
    public UUID getServicePlanId() {
        return servicePlanId;
    }

    public void setServicePlanId(UUID servicePlanId) {
        this.servicePlanId = servicePlanId;
    }
    
    @Override
    public String toString() {
        return ReflectionToStringBuilder.toString(this, ToStringStyle.JSON_STYLE);
    }
}
