package net.tirasa.connid.bundles.azure.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class AssignedLicense {

    @JsonProperty
    private String skuId;

    @JsonProperty
    private List<String> disabledPlans = new ArrayList<>();

    public String getSkuId() {
        return skuId;
    }

    public void setSkuId(final String skuId) {
        this.skuId = skuId;
    }

    public List<String> getDisabledPlans() {
        return disabledPlans;
    }

    public void setDisabledPlans(final List<String> disabledPlans) {
        this.disabledPlans = disabledPlans;
    }

}
