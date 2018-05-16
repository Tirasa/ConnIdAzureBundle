/**
 * Copyright © 2018 ConnId (connid-dev@googlegroups.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.connid.bundles.azure.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import net.tirasa.connid.bundles.azure.utils.AzureAttributes;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.Attribute;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class User implements AzureObject {

    @JsonProperty
    private String objectId;

    @JsonProperty
    private String displayName;

    @JsonProperty
    private String objectType;

    @JsonProperty
    private Boolean accountEnabled;

    @JsonProperty
    private String city;

    @JsonProperty
    private String country;

    @JsonProperty
    private String department;

    @JsonProperty
    private Boolean dirSyncEnabled;

    @JsonProperty
    private String facsimileTelephoneNumber;

    @JsonProperty
    private String givenName;

    @JsonProperty
    private String immutableId;

    @JsonProperty
    private String jobTitle;

    @JsonProperty
    private String lastDirSyncTime;

    @JsonProperty
    private String mail;

    @JsonProperty
    private String mailNickname;

    @JsonProperty
    private String mobile;

    @JsonProperty
    private String passwordPolicies;

    @JsonProperty
    private String physicalDeliveryOfficeName;

    @JsonProperty
    private String postalCode;

    @JsonProperty
    private String preferredLanguage;

    @JsonProperty
    private String state;

    @JsonProperty
    private String streetAddress;

    @JsonProperty
    private String surname;

    @JsonProperty
    private String telephoneNumber;

    @JsonProperty
    private String usageLocation;

    @JsonProperty
    private String userPrincipalName;

    @JsonProperty
    private String companyName;

    @JsonProperty
    private String creationType;

    @JsonProperty
    private String employeeId;

    @JsonProperty
    private Boolean isCompromised;

    @JsonProperty
    private String onPremisesDistinguishedName;

    @JsonProperty
    private String onPremisesSecurityIdentifier;

    @JsonProperty
    private String refreshTokensValidFromDateTime;

    @JsonProperty
    private String showInAddressList;

    @JsonProperty
    private String sipProxyAddress;

    @JsonProperty
    private String userType;

    // complex
    @JsonProperty
    private PasswordProfile passwordProfile;

    // lists
    @JsonProperty
    private List<Object> userIdentities = new ArrayList<>();

    @JsonProperty
    private List<Object> signInNames = new ArrayList<>();

    @JsonProperty
    private List<String> otherMails = new ArrayList<>();

    @JsonProperty
    private List<ProvisionedPlan> provisionedPlans = new ArrayList<>();

    @JsonProperty
    private List<Object> provisioningErrors = new ArrayList<>();

    @JsonProperty
    private List<String> proxyAddresses = new ArrayList<>();

    @JsonProperty
    private List<AssignedLicense> assignedLicenses = new ArrayList<>();

    @JsonProperty
    private List<AssignedPlan> assignedPlans = new ArrayList<>();

    @JsonIgnore
    private GuardedString password;

    @JsonIgnore
    private byte[] thumbnailPhoto;

    /**
     * @return The immutableId of this user.
     */
    public String getImmutableId() {
        return immutableId;
    }

    /**
     * @param immutableId the immutableId of a user object.
     */
    public void setImmutableId(String immutableId) {
        this.immutableId = immutableId;
    }

    /**
     * @return The objectType of this User.
     */
    public String getObjectType() {
        return objectType;
    }

    /**
     * @param objectType The objectType to set to this User object.
     */
    public void setObjectType(String objectType) {
        this.objectType = objectType;
    }

    /**
     * @return The userPrincipalName of this User.
     */
    public String getUserPrincipalName() {
        return userPrincipalName;
    }

    /**
     * @param userPrincipalName The userPrincipalName to set to this User object.
     */
    public void setUserPrincipalName(String userPrincipalName) {
        this.userPrincipalName = userPrincipalName;
    }

    /**
     * @return The usageLocation of this User.
     */
    public String getUsageLocation() {
        return usageLocation;
    }

    /**
     * @param usageLocation The usageLocation to set to this User object.
     */
    public void setUsageLocation(String usageLocation) {
        this.usageLocation = usageLocation;
    }

    /**
     * @return The telephoneNumber of this User.
     */
    public String getTelephoneNumber() {
        return telephoneNumber;
    }

    /**
     * @param telephoneNumber The telephoneNumber to set to this User object.
     */
    public void setTelephoneNumber(String telephoneNumber) {
        this.telephoneNumber = telephoneNumber;
    }

    /**
     * @return The surname of this User.
     */
    public String getSurname() {
        return surname;
    }

    /**
     * @param surname The surname to set to this User AzureObject.
     */
    public void setSurname(String surname) {
        this.surname = surname;
    }

    /**
     * @return The streetAddress of this User.
     */
    public String getStreetAddress() {
        return streetAddress;
    }

    /**
     * @param streetAddress The streetAddress to set to this User.
     */
    public void setStreetAddress(String streetAddress) {
        this.streetAddress = streetAddress;
    }

    /**
     * @return The state of this User.
     */
    public String getState() {
        return state;
    }

    /**
     * @param state The state to set to this User object.
     */
    public void setState(String state) {
        this.state = state;
    }

    /**
     * @return The preferredLanguage of this User.
     */
    public String getPreferredLanguage() {
        return preferredLanguage;
    }

    /**
     * @param preferredLanguage The preferredLanguage to set to this User.
     */
    public void setPreferredLanguage(String preferredLanguage) {
        this.preferredLanguage = preferredLanguage;
    }

    /**
     * @return The postalCode of this User.
     */
    public String getPostalCode() {
        return postalCode;
    }

    /**
     * @param postalCode The postalCode to set to this User.
     */
    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    /**
     * @return The physicalDeliveryOfficeName of this User.
     */
    public String getPhysicalDeliveryOfficeName() {
        return physicalDeliveryOfficeName;
    }

    /**
     * @param physicalDeliveryOfficeName The physicalDeliveryOfficeName to set to this User AzureObject.
     */
    public void setPhysicalDeliveryOfficeName(String physicalDeliveryOfficeName) {
        this.physicalDeliveryOfficeName = physicalDeliveryOfficeName;
    }

    /**
     * @return The passwordPolicies of this User.
     */
    public String getPasswordPolicies() {
        return passwordPolicies;
    }

    /**
     * @param passwordPolicies The passwordPolicies to set to this User object.
     */
    public void setPasswordPolicies(String passwordPolicies) {
        this.passwordPolicies = passwordPolicies;
    }

    /**
     * @return The mobile of this User.
     */
    public String getMobile() {
        return mobile;
    }

    /**
     * @param mobile The mobile to set to this User object.
     */
    public void setMobile(String mobile) {
        this.mobile = mobile;
    }

    /**
     * @return The mail of this User.
     */
    public String getMail() {
        return mail;
    }

    /**
     * @param mail The mail to set to this User object.
     */
    public void setMail(String mail) {
        this.mail = mail;
    }

    /**
     * @return The mail of this User.
     */
    public String getMailNickname() {
        return mailNickname;
    }

    /**
     * @param mailnNickName The mail to set to this User object.
     */
    public void setMailNickname(String mailnNickName) {
        mailNickname = mailnNickName;
    }

    /**
     * @return The jobTitle of this User.
     */
    public String getJobTitle() {
        return jobTitle;
    }

    /**
     * @param jobTitle The jobTitle to set to this User AzureObject.
     */
    public void setJobTitle(String jobTitle) {
        this.jobTitle = jobTitle;
    }

    /**
     * @return The givenName of this User.
     */
    public String getGivenName() {
        return givenName;
    }

    /**
     * @param givenName The givenName to set to this User.
     */
    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    /**
     * @return The facsimileTelephoneNumber of this User.
     */
    public String getFacsimileTelephoneNumber() {
        return facsimileTelephoneNumber;
    }

    /**
     * @param facsimileTelephoneNumber The facsimileTelephoneNumber to set to this User AzureObject.
     */
    public void setFacsimileTelephoneNumber(String facsimileTelephoneNumber) {
        this.facsimileTelephoneNumber = facsimileTelephoneNumber;
    }

    /**
     * @return The dirSyncEnabled of this User.
     */
    public Boolean getDirSyncEnabled() {
        return dirSyncEnabled;
    }

    /**
     * @param dirSyncEnabled The dirSyncEnabled to set to this User.
     */
    public void setDirSyncEnabled(Boolean dirSyncEnabled) {
        this.dirSyncEnabled = dirSyncEnabled;
    }

    /**
     * @return The department of this User.
     */
    public String getDepartment() {
        return department;
    }

    /**
     * @param department The department to set to this User.
     */
    public void setDepartment(String department) {
        this.department = department;
    }

    /**
     * @return The lastDirSyncTime of this User.
     */
    public String getLastDirSyncTime() {
        return lastDirSyncTime;
    }

    /**
     * @param lastDirSyncTime The lastDirSyncTime to set to this User.
     */
    public void setLastDirSyncTime(String lastDirSyncTime) {
        this.lastDirSyncTime = lastDirSyncTime;
    }

    /**
     * @return The country of this User.
     */
    public String getCountry() {
        return country;
    }

    /**
     * @param country The country to set to this User.
     */
    public void setCountry(String country) {
        this.country = country;
    }

    /**
     * @return The city of this User.
     */
    public String getCity() {
        return city;
    }

    /**
     * @param city The city to set to this User.
     */
    public void setCity(String city) {
        this.city = city;
    }

    /**
     * @return The accountEnabled attribute of this User.
     */
    public Boolean getAccountEnabled() {
        return accountEnabled;
    }

    /**
     * @param accountEnabled The accountEnabled to set to this User.
     */
    public void setAccountEnabled(Boolean accountEnabled) {
        this.accountEnabled = accountEnabled;
    }

    public PasswordProfile getPasswordProfile() {
        return passwordProfile;
    }

    public void setPasswordProfile(PasswordProfile PasswordProfile) {
        this.passwordProfile = PasswordProfile;
    }

    public GuardedString getPassword() {
        return password;
    }

    public void setPassword(GuardedString password) {
        this.password = password;
    }

    public String getCompanyName() {
        return companyName;
    }

    public void setCompanyName(String companyName) {
        this.companyName = companyName;
    }

    public String getCreationType() {
        return creationType;
    }

    public void setCreationType(String creationType) {
        this.creationType = creationType;
    }

    public String getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(String employeeId) {
        this.employeeId = employeeId;
    }

    public Boolean getIsCompromised() {
        return isCompromised;
    }

    public void setIsCompromised(Boolean isCompromised) {
        this.isCompromised = isCompromised;
    }

    public String getOnPremisesDistinguishedName() {
        return onPremisesDistinguishedName;
    }

    public void setOnPremisesDistinguishedName(String onPremisesDistinguishedName) {
        this.onPremisesDistinguishedName = onPremisesDistinguishedName;
    }

    public String getOnPremisesSecurityIdentifier() {
        return onPremisesSecurityIdentifier;
    }

    public void setOnPremisesSecurityIdentifier(String onPremisesSecurityIdentifier) {
        this.onPremisesSecurityIdentifier = onPremisesSecurityIdentifier;
    }

    public String getRefreshTokensValidFromDateTime() {
        return refreshTokensValidFromDateTime;
    }

    public void setRefreshTokensValidFromDateTime(String refreshTokensValidFromDateTime) {
        this.refreshTokensValidFromDateTime = refreshTokensValidFromDateTime;
    }

    public String getShowInAddressList() {
        return showInAddressList;
    }

    public void setShowInAddressList(String showInAddressList) {
        this.showInAddressList = showInAddressList;
    }

    public String getSipProxyAddress() {
        return sipProxyAddress;
    }

    public void setSipProxyAddress(String sipProxyAddress) {
        this.sipProxyAddress = sipProxyAddress;
    }

    public String getUserType() {
        return userType;
    }

    public void setUserType(String userType) {
        this.userType = userType;
    }

    public List<AssignedLicense> getAssignedLicenses() {
        return assignedLicenses;
    }

    public void setAssignedLicenses(final List<AssignedLicense> assignedLicenses) {
        this.assignedLicenses = assignedLicenses;
    }

    public List<AssignedPlan> getAssignedPlans() {
        return assignedPlans;
    }

    public void setAssignedPlans(final List<AssignedPlan> assignedPlans) {
        this.assignedPlans = assignedPlans;
    }

    public List<String> getOtherMails() {
        return otherMails;
    }

    public void setOtherMails(final List<String> otherMails) {
        this.otherMails = otherMails;
    }

    public List<ProvisionedPlan> getProvisionedPlans() {
        return provisionedPlans;
    }

    public void setProvisionedPlans(final List<ProvisionedPlan> provisionedPlans) {
        this.provisionedPlans = provisionedPlans;
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

    public List<Object> getSignInNames() {
        return signInNames;
    }

    public void setSignInNames(final List<Object> signInNames) {
        this.signInNames = signInNames;
    }

    public byte[] getThumbnailPhoto() {
        return thumbnailPhoto;
    }

    public void setThumbnailPhoto(final byte[] thumbnailPhoto) {
        this.thumbnailPhoto = thumbnailPhoto == null ? null : thumbnailPhoto.clone();
    }

    public List<Object> getUserIdentities() {
        return userIdentities;
    }

    public void setUserIdentities(final List<Object> userIdentities) {
        this.userIdentities = userIdentities;
    }

    public String getDisplayName() {
        return displayName;
    }

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
    public Set<Attribute> toAttributes() throws IllegalArgumentException, IllegalAccessException {
        Set<Attribute> attrs = new HashSet<>();

        Field[] fields = User.class.getDeclaredFields();
        for (Field field : fields) {
            if (field.getAnnotation(JsonIgnore.class) == null) {
                field.setAccessible(true);
                if (field.getName().equals(AzureAttributes.USER_PASSWORD_PROFILE) && passwordProfile != null) {
                    attrs.addAll(passwordProfile.toAttributes());
                } else {
                    attrs.add(AzureAttributes.buildAttributeFromClassField(field, this).build());
                }
            }
        }

        return attrs;
    }

    @Override
    public void fromAttributes(final Set<Attribute> attributes) {
        for (Attribute attribute : attributes) {
            if (!CollectionUtil.isEmpty(attribute.getValue())) {
                List<Object> values = attribute.getValue();
                String name = attribute.getName();

                doSetAttribute(name, values);
            }
        }
    }

    private PasswordProfile createPasswordProfile(final String value) {
        GuardedString newValue = AzureUtils.createPassword(value);
        password = newValue;
        passwordProfile = new PasswordProfile();
        passwordProfile.setPassword(newValue);
        passwordProfile.setEnforceChangePasswordPolicy(false);
        passwordProfile.setForceChangePasswordNextLogin(false);
        return passwordProfile;
    }

    private PasswordProfile createPasswordProfile(final GuardedString value) {
        password = value;
        passwordProfile = new PasswordProfile();
        passwordProfile.setPassword(value);
        passwordProfile.setEnforceChangePasswordPolicy(false);
        passwordProfile.setForceChangePasswordNextLogin(false);
        return passwordProfile;
    }

    @SuppressWarnings("unchecked")
    private void doSetAttribute(final String name, final List<Object> values) {
        Object value = values.get(0);
        switch (name) {
            case "displayName":
                displayName =
                        String.class.cast(value);
                break;
            case "passwordProfile":
                passwordProfile = value instanceof GuardedString
                        ? createPasswordProfile(GuardedString.class.cast(value))
                        : createPasswordProfile(String.class.cast(value));
                break;
            case "__PASSWORD__":
                passwordProfile = value instanceof GuardedString
                        ? createPasswordProfile(GuardedString.class.cast(value))
                        : createPasswordProfile(String.class.cast(value));
                break;
            case "password":
                passwordProfile = value instanceof GuardedString
                        ? createPasswordProfile(GuardedString.class.cast(value))
                        : createPasswordProfile(String.class.cast(value));
                break;
            case "objectId":
                objectId =
                        String.class.cast(value);
                break;
            case "objectType":
                objectType =
                        String.class.cast(value);
                break;
            case "accountEnabled":
                accountEnabled =
                        Boolean.class.cast(value);
                break;
            case "city":
                city =
                        String.class.cast(value);
                break;
            case "country":
                country =
                        String.class.cast(value);
                break;
            case "department":
                department =
                        String.class.cast(value);
                break;
            case "dirSyncEnabled":
                dirSyncEnabled =
                        Boolean.class.cast(value);
                break;
            case "facsimileTelephoneNumber":
                facsimileTelephoneNumber =
                        String.class.cast(value);
                break;
            case "givenName":
                givenName =
                        String.class.cast(value);
                break;
            case "immutableId":
                immutableId =
                        String.class.cast(value);
                break;
            case "jobTitle":
                jobTitle =
                        String.class.cast(value);
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
            case "mobile":
                mobile =
                        String.class.cast(value);
                break;
            case "passwordPolicies":
                passwordPolicies =
                        String.class.cast(value);
                break;
            case "preferredLanguage":
                preferredLanguage =
                        String.class.cast(value);
                break;
            case "physicalDeliveryOfficeName":
                physicalDeliveryOfficeName =
                        String.class.cast(value);
                break;
            case "postalCode":
                postalCode =
                        String.class.cast(value);
                break;
            case "state":
                state =
                        String.class.cast(value);
                break;
            case "streetAddress":
                streetAddress =
                        String.class.cast(value);
                break;
            case "surname":
                surname =
                        String.class.cast(value);
                break;
            case "telephoneNumber":
                telephoneNumber =
                        String.class.cast(value);
                break;
            case "usageLocation":
                usageLocation =
                        String.class.cast(value);
                break;
            case "userPrincipalName":
                userPrincipalName =
                        String.class.cast(value);
                break;
            case "companyName":
                companyName =
                        String.class.cast(value);
                break;
            case "creationType":
                creationType =
                        String.class.cast(value);
                break;
            case "employeeId":
                employeeId =
                        String.class.cast(value);
                break;
            case "isCompromised":
                isCompromised =
                        Boolean.class.cast(value);
                break;
            case "onPremisesDistinguishedName":
                onPremisesDistinguishedName =
                        String.class.cast(value);
                break;
            case "onPremisesSecurityIdentifier":
                onPremisesSecurityIdentifier =
                        String.class.cast(value);
                break;
            case "refreshTokensValidFromDateTime":
                refreshTokensValidFromDateTime =
                        String.class.cast(value);
                break;
            case "showInAddressList":
                showInAddressList =
                        String.class.cast(value);
                break;
            case "sipProxyAddress":
                sipProxyAddress =
                        String.class.cast(value);
                break;
            case "thumbnailPhoto":
                thumbnailPhoto = (byte[]) value;
                break;
            case "userType":
                userType =
                        String.class.cast(value);
                break;
            case "userIdentities":
                userIdentities =
                        new ArrayList<>(values);
                break;
            case "signInNames":
                signInNames =
                        new ArrayList<>(values);
                break;
            case "otherMails":
                otherMails =
                        new ArrayList<>((List<String>) (Object) values);
                break;
            case "provisionedPlans":
                provisionedPlans =
                        new ArrayList<>((List<ProvisionedPlan>) (Object) values);
                break;
            case "provisioningErrors":
                provisioningErrors =
                        new ArrayList<>(values);
                break;
            case "proxyAddresses":
                proxyAddresses =
                        new ArrayList<>((List<String>) (Object) values);
                break;
            case "assignedLicenses":
                assignedLicenses =
                        new ArrayList<>((List<AssignedLicense>) (Object) values);
                break;
            case "assignedPlans":
                assignedPlans =
                        new ArrayList<>((List<AssignedPlan>) (Object) values);
                break;
        }
    }

    @Override
    public String toString() {
        return "User{" + "objectId=" + objectId + ", displayName=" + displayName + ", objectType=" + objectType
                + ", accountEnabled=" + accountEnabled + ", city=" + city + ", country=" + country + ", department="
                + department + ", dirSyncEnabled=" + dirSyncEnabled + ", facsimileTelephoneNumber="
                + facsimileTelephoneNumber + ", givenName=" + givenName + ", immutableId=" + immutableId + ", jobTitle="
                + jobTitle + ", lastDirSyncTime=" + lastDirSyncTime + ", mail=" + mail + ", mailNickname="
                + mailNickname + ", mobile=" + mobile + ", passwordPolicies=" + passwordPolicies
                + ", physicalDeliveryOfficeName=" + physicalDeliveryOfficeName + ", postalCode=" + postalCode
                + ", preferredLanguage=" + preferredLanguage + ", state=" + state + ", streetAddress=" + streetAddress
                + ", surname=" + surname + ", telephoneNumber=" + telephoneNumber + ", usageLocation=" + usageLocation
                + ", userPrincipalName=" + userPrincipalName + ", companyName=" + companyName + ", creationType="
                + creationType + ", employeeId=" + employeeId + ", isCompromised=" + isCompromised
                + ", onPremisesDistinguishedName=" + onPremisesDistinguishedName + ", onPremisesSecurityIdentifier="
                + onPremisesSecurityIdentifier + ", refreshTokensValidFromDateTime=" + refreshTokensValidFromDateTime
                + ", showInAddressList=" + showInAddressList + ", sipProxyAddress=" + sipProxyAddress + ", userType="
                + userType + ", passwordProfile=" + passwordProfile + ", userIdentities=" + userIdentities
                + ", signInNames=" + signInNames + ", otherMails=" + otherMails + ", provisionedPlans="
                + provisionedPlans + ", provisioningErrors=" + provisioningErrors + ", proxyAddresses=" + proxyAddresses
                + ", assignedLicenses=" + assignedLicenses + ", assignedPlans=" + assignedPlans + ", password="
                + password + ", thumbnailPhoto=" + thumbnailPhoto
                + '}';
    }

}
