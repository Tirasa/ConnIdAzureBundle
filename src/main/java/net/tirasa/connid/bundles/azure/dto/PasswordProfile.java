package net.tirasa.connid.bundles.azure.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.HashSet;
import java.util.Set;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.SecurityUtil;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;

@JsonIgnoreProperties(ignoreUnknown = true)
public class PasswordProfile {

    @JsonProperty
    private String password;

    @JsonProperty
    private Boolean forceChangePasswordNextLogin;

    @JsonProperty
    private Boolean enforceChangePasswordPolicy;

    public String getPassword() {
        return password != null ? SecurityUtil.decrypt(AzureUtils.createPassword(password)) : null;
    }

    public void setPassword(final GuardedString password) {
        this.password = password != null ? AzureUtils.getPasswordValue(password) : null;
    }

    public Boolean getForceChangePasswordNextLogin() {
        return forceChangePasswordNextLogin;
    }

    public void setForceChangePasswordNextLogin(final Boolean forceChangePasswordNextLogin) {
        this.forceChangePasswordNextLogin = forceChangePasswordNextLogin;
    }

    public Boolean getEnforceChangePasswordPolicy() {
        return enforceChangePasswordPolicy;
    }

    public void setEnforceChangePasswordPolicy(final Boolean enforceChangePasswordPolicy) {
        this.enforceChangePasswordPolicy = enforceChangePasswordPolicy;
    }

    public Set<Attribute> toAttributes() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(AttributeBuilder.build("password", password == null
                ? null
                : new GuardedString(password.toCharArray())));
        return attrs;
    }

    @Override
    public boolean equals(final Object obj) {
        return EqualsBuilder.reflectionEquals(this, obj);
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public String toString() {
        return "PasswordProfile [password=" + password + ", forceChangePasswordNextLogin="
                + forceChangePasswordNextLogin + "]";
    }

}
