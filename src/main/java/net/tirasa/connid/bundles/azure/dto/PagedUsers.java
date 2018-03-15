package net.tirasa.connid.bundles.azure.dto;

import java.util.Collections;
import java.util.List;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.identityconnectors.common.StringUtil;

public class PagedUsers implements AzurePagedObject {

    private List<User> users;

    private String skipToken;

    public List<User> getUsers() {
        return Collections.unmodifiableList(users);
    }

    public void setUsers(List<User> user) {
        this.users = user;
    }

    @Override
    public String getSkipToken() {
        return skipToken;
    }

    @Override
    public void setSkipToken(String skipToken) {
        this.skipToken = skipToken;
    }

    public Boolean hasMoreResults() {
        return StringUtil.isNotBlank(getSkipToken());
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
        return ReflectionToStringBuilder.toString(this, ToStringStyle.JSON_STYLE);
    }

}
