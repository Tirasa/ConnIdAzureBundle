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
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import net.tirasa.connid.bundles.azure.utils.AzureAttributes;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.framework.common.objects.Attribute;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class Group implements AzureObject {

    @JsonProperty
    private String objectId;

    @JsonProperty
    private String displayName;

    @JsonProperty
    private String objectType;

    @JsonProperty
    private String description;

    @JsonProperty
    private Boolean dirSyncEnabled;

    @JsonProperty
    private String lastDirSyncTime;

    @JsonProperty
    private String mail;

    @JsonProperty
    private String mailNickname;

    @JsonProperty
    private Boolean mailEnabled;

    @JsonProperty
    private String onPremisesSecurityIdentifier;

    @JsonProperty
    private List<Object> provisioningErrors = new ArrayList<>();

    @JsonProperty
    private List<String> proxyAddresses = new ArrayList<>();

    @JsonProperty
    private Boolean securityEnabled;

    /**
     * @return The dirSyncEnabled attribute of this Group.
     */
    public Boolean getDirSyncEnabled() {
        return dirSyncEnabled;
    }

    /**
     * @param dirSyncEnabled The dirSyncEnabled to set.
     */
    public void setDirSyncEnabled(final Boolean dirSyncEnabled) {
        this.dirSyncEnabled = dirSyncEnabled;
    }

    /**
     * @return The description of the Group.
     */
    public String getDescription() {
        return description;
    }

    /**
     * @param description The description to set
     */
    public void setDescription(final String description) {
        this.description = description;
    }

    /**
     * @return The lastDirSyncTime of this Group.
     */
    public String getLastDirSyncTime() {
        return lastDirSyncTime;
    }

    /**
     * @param lastDirSyncTime The lastDirSyncTime to set to this Group.
     */
    public void setLastDirSyncTime(final String lastDirSyncTime) {
        this.lastDirSyncTime = lastDirSyncTime;
    }

    /**
     * @return The mail attribute of this Group.
     */
    public String getMail() {
        return mail;
    }

    /**
     * @param mail The mail to set to this Group.
     */
    public void setMail(final String mail) {
        this.mail = mail;
    }

    /**
     * @return The mailEnabled attribute of this Group.
     */
    public Boolean getMailEnabled() {
        return mailEnabled;
    }

    /**
     * @param mailEnabled The mailEnabled to set to this Group.
     */
    public void setMailEnabled(final Boolean mailEnabled) {
        this.mailEnabled = mailEnabled;
    }

    /**
     * @return The securityEnabled attribute of this Group.
     */
    public Boolean getSecurityEnabled() {
        return securityEnabled;
    }

    /**
     * @param securityEnabled The securityEnabled to set to this Group.
     */
    public void setSecurityEnabled(final Boolean securityEnabled) {
        this.securityEnabled = securityEnabled;
    }

    public String getMailNickname() {
        return mailNickname;
    }

    public void setMailNickname(final String mailNickname) {
        this.mailNickname = mailNickname;
    }

    public String getOnPremisesSecurityIdentifier() {
        return onPremisesSecurityIdentifier;
    }

    public void setOnPremisesSecurityIdentifier(final String onPremisesSecurityIdentifier) {
        this.onPremisesSecurityIdentifier = onPremisesSecurityIdentifier;
    }

    public List<Object> getProvisioningErrors() {
        return provisioningErrors;
    }

    public void setProvisioningErrors(final List<Object> provisioningErrors) {
        this.provisioningErrors = provisioningErrors;
    }

    public List<String> getProxyAddresses() {
        return proxyAddresses;
    }

    public void setProxyAddresses(final List<String> proxyAddresses) {
        this.proxyAddresses = proxyAddresses;
    }

    public String getObjectType() {
        return objectType;
    }

    public void setObjectType(final String objectType) {
        this.objectType = objectType;
    }

    @Override
    public String getDisplayName() {
        return displayName;
    }

    @Override
    public void setDisplayName(final String displayName) {
        this.displayName = displayName;
    }

    @Override
    public String getObjectId() {
        return objectId;
    }

    @Override
    public void setObjectId(final String objectId) {
        this.objectId = objectId;
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.toString(this, ToStringStyle.JSON_STYLE);
    }

    @Override
    public Set<Attribute> toAttributes() throws IllegalArgumentException, IllegalAccessException {
        Set<Attribute> attrs = new HashSet<>();

        Field[] fields = Group.class.getDeclaredFields();
        for (Field field : fields) {
            field.setAccessible(true);
            attrs.add(AzureAttributes.buildAttributeFromClassField(field, this).build());
        }

        return attrs;
    }

    @Override
    public void fromAttributes(Set<Attribute> attributes) {
        for (Attribute attribute : attributes) {
            if (!CollectionUtil.isEmpty(attribute.getValue())) {
                List<Object> values = attribute.getValue();
                String name = attribute.getName();

                doSetAttribute(name, values);
            }

        }
    }

    @SuppressWarnings("unchecked")
    private void doSetAttribute(final String name, final List<Object> values) {
        Object value = values.get(0);
        switch (name) {
            case "displayName":
                displayName =
                        String.class.cast(value);
                break;
            case "objectId":
                objectId =
                        String.class.cast(value);
                break;
            case "objectType":
                objectType =
                        String.class.cast(value);
                break;
            case "dirSyncEnabled":
                dirSyncEnabled =
                        Boolean.class.cast(value);
                break;
            case "lastDirSyncTime":
                lastDirSyncTime =
                        String.class.cast(value);
                break;
            case "mail":
                mail =
                        String.class.cast(value);
                break;
            case "mailNickname":
                mailNickname =
                        String.class.cast(value);
                break;
            case "onPremisesSecurityIdentifier":
                onPremisesSecurityIdentifier =
                        String.class.cast(value);
                break;
            case "provisioningErrors":
                provisioningErrors =
                        new ArrayList<>(values);
                break;
            case "proxyAddresses":
                proxyAddresses =
                        new ArrayList<>((List<String>) (List<?>) values);
                break;
            case "description":
                description =
                        String.class.cast(value);
                break;
            case "assignedPlans":
                mailEnabled =
                        Boolean.class.cast(value);
                break;
            case "securityEnabled":
                securityEnabled =
                        Boolean.class.cast(value);
                break;

        }
    }

}
