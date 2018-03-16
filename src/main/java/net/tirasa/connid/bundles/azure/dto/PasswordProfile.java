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
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.HashSet;
import java.util.Set;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
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

    private GuardedString asGuardedString() {
        return password == null
                ? null
                : new GuardedString(password.toCharArray());
    }

    public Set<Attribute> toAttributes() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(AttributeBuilder.build("password", asGuardedString()));
        return attrs;
    }

    @Override
    public String toString() {
        return "PasswordProfile [password=" + asGuardedString() + ", forceChangePasswordNextLogin="
                + forceChangePasswordNextLogin + "]";
    }

}
