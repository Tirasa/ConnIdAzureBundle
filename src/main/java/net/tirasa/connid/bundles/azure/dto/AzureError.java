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
import javax.ws.rs.core.Response;
import net.tirasa.connid.bundles.azure.service.NoSuchEntityException;
import net.tirasa.connid.bundles.azure.utils.AzureUtils;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AzureError {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Message {

        @JsonProperty("lang")
        public String lang;

        @JsonProperty("value")
        public String value;

    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ODataError {

        @JsonProperty("code")
        public String code;

        @JsonProperty("message")
        public Message message;

        @JsonProperty("values")
        public String values;

    }

    @JsonProperty("odata.error")
    public ODataError odata_error;

    @JsonProperty("message")
    public Message message;

    public static String log(final String action, final Response response) {
        try {
            AzureError error = AzureUtils.MAPPER.readValue(
                    response.readEntity(String.class), AzureError.class);
            ODataError oError = error.odata_error;
            return String.format("Failed to %s: status=%d code=%s reason=%s",
                    action,
                    response.getStatus(),
                    oError == null ? "?" : oError.code,
                    oError == null ? "?" : oError.message.value);
        } catch (Exception e) {
            String returnMessage = "Failed to " + action + "with response: " + response.readEntity(String.class);
            return returnMessage.replaceAll("\\{", "'{'").replaceAll("\\}", "'}'");
        }
    }

    public static void sendError(final String action, final Response response) {
        String errorCode = null;
        try {
            AzureError error = AzureUtils.MAPPER.readValue(
                    response.readEntity(String.class), AzureError.class);
            ODataError oError = error.odata_error;
            errorCode = oError.code;
        } catch (Exception e) {
            String returnMessage = "Failed to " + action + "with response: " + response.readEntity(String.class);
            throw new RuntimeException(returnMessage.replaceAll("\\{", "'{'").replaceAll("\\}", "'}'"));
        }

        switch (errorCode) {
            case "Request_ResourceNotFound":
                throw new NoSuchEntityException(response.readEntity(String.class));

            default:
                throw new RuntimeException(response.readEntity(String.class));
        }
    }
}
