package net.tirasa.connid.bundles.azure.service;

import org.identityconnectors.framework.common.exceptions.ConnectorException;

public class NoSuchEntityException extends ConnectorException {

    private static final long serialVersionUID = 3058540779827108313L;

    /**
     * Constructs a new NoSuchEntityException with the specified error message.
     *
     * @param message
     * Describes the error encountered.
     */
    public NoSuchEntityException(final String message) {
        super(message);
    }

}
