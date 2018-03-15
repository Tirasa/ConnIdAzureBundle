package net.tirasa.connid.bundles.azure.dto;

import java.util.Set;
import org.identityconnectors.framework.common.objects.Attribute;

public interface AzureObject {

    String getDisplayName();

    String getObjectId();

    void setDisplayName(String displayName);

    void setObjectId(String objectId);

    Set<Attribute> toAttributes() throws IllegalArgumentException, IllegalAccessException;

    void fromAttributes(Set<Attribute> attributes);
}
