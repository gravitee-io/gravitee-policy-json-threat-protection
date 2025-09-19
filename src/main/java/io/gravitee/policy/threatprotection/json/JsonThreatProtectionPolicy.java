/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
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
package io.gravitee.policy.threatprotection.json;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.SimpleReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequestContent;
import java.io.IOException;
import java.util.Collections;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JsonThreatProtectionPolicy {

    public static final String BAD_REQUEST = "Bad Request";
    public static final String JSON_THREAT_DETECTED_KEY = "JSON_THREAT_DETECTED";
    public static final String JSON_THREAT_MAX_DEPTH_KEY = "JSON_THREAT_MAX_DEPTH";
    public static final String JSON_THREAT_MAX_ENTRIES_KEY = "JSON_THREAT_MAX_ENTRIES";
    public static final String JSON_THREAT_MAX_NAME_LENGTH_KEY = "JSON_THREAT_MAX_NAME_LENGTH";
    public static final String JSON_THREAT_MAX_VALUE_LENGTH_KEY = "JSON_THREAT_MAX_VALUE_LENGTH";
    public static final String JSON_MAX_ARRAY_SIZE_KEY = "JSON_MAX_ARRAY_SIZE";

    private static final JsonFactory jsonFactory = new JsonFactory();

    private JsonThreatProtectionPolicyConfiguration configuration;

    public JsonThreatProtectionPolicy(JsonThreatProtectionPolicyConfiguration configuration) {
        this.configuration = configuration;
        jsonFactory.configure(JsonParser.Feature.STRICT_DUPLICATE_DETECTION, configuration.isPreventDuplicateKey());
    }

    @OnRequestContent
    public ReadWriteStream<Buffer> onRequestContent(Request request, PolicyChain policyChain) {
        if (request.headers().getOrDefault(HttpHeaders.CONTENT_TYPE, Collections.emptyList()).contains(MediaType.APPLICATION_JSON)) {
            // The policy is only applicable to json content type.
            return new BufferedReadWriteStream() {
                final Buffer buffer = Buffer.buffer();

                @Override
                public SimpleReadWriteStream<Buffer> write(Buffer content) {
                    buffer.appendBuffer(content);
                    return this;
                }

                @Override
                public void end() {
                    try {
                        validateJson(buffer.toString());

                        if (buffer.length() > 0) {
                            super.write(buffer);
                        }
                        super.end();
                    } catch (JsonException e) {
                        policyChain.streamFailWith(
                            PolicyResult.failure(e.getKey(), HttpStatusCode.BAD_REQUEST_400, BAD_REQUEST, MediaType.TEXT_PLAIN)
                        );
                    } catch (Exception e) {
                        policyChain.streamFailWith(
                            PolicyResult.failure(
                                JSON_THREAT_DETECTED_KEY,
                                HttpStatusCode.BAD_REQUEST_400,
                                BAD_REQUEST,
                                MediaType.TEXT_PLAIN
                            )
                        );
                    }
                }
            };
        }

        return null;
    }

    public void validateJson(String json) throws JsonException {
        try {
            JsonParser parser = jsonFactory.createParser(json);
            JsonDepthCounter depthCounter = new JsonDepthCounter();

            JsonToken token;
            while ((token = parser.nextToken()) != null) {
                validate(depthCounter, token, parser);
            }
        } catch (IOException e) {
            throw new JsonException(JSON_THREAT_DETECTED_KEY, "Invalid json data");
        }
    }

    public void validate(JsonDepthCounter depthCounter, JsonToken token, JsonParser parser) throws IOException, JsonException {
        switch (token) {
            case START_OBJECT:
                validateObject(depthCounter, parser);
                break;
            case START_ARRAY:
                validateArray(depthCounter, parser);
                break;
            case FIELD_NAME:
                validateName(parser.getCurrentName());
                break;
            case VALUE_STRING:
                validateValue(parser.getText());
                break;
        }
    }

    public void validateObject(JsonDepthCounter depthCounter, JsonParser parser) throws JsonException {
        JsonToken token;

        try {
            int fieldCount = 0;
            depthCounter.increment();
            validateDepth(depthCounter.getDepth());

            while ((token = parser.nextToken()) != JsonToken.END_OBJECT) {
                validate(depthCounter, token, parser);

                if (token == JsonToken.FIELD_NAME) {
                    validateFieldCount(++fieldCount);
                }
            }

            depthCounter.decrement();
        } catch (IOException e) {
            throw new JsonException(JSON_THREAT_DETECTED_KEY, "Invalid json data");
        }
    }

    public void validateDepth(int depth) throws JsonException {
        if (configuration.hasMaxDepth() && depth > configuration.getMaxDepth()) {
            throw new JsonException(JSON_THREAT_MAX_DEPTH_KEY, "Max depth exceeded for json (max: " + configuration.getMaxDepth() + ")");
        }
    }

    public void validateFieldCount(int currentCount) throws JsonException {
        if (configuration.hasMaxEntries() && currentCount > configuration.getMaxEntries()) {
            throw new JsonException(
                JSON_THREAT_MAX_ENTRIES_KEY,
                "Max number of entries exceeded for json (max: " + configuration.getMaxEntries() + ")"
            );
        }
    }

    private void validateName(String name) throws JsonException {
        if (configuration.hasMaxNameLength()) {
            if (name.length() > configuration.getMaxNameLength()) {
                throw new JsonException(
                    JSON_THREAT_MAX_NAME_LENGTH_KEY,
                    "Max length exceeded for field name [" + name + "] (max: " + configuration.getMaxNameLength() + ")"
                );
            }
        }
    }

    private void validateValue(String value) throws JsonException {
        if (configuration.hasMaxValueLength()) {
            if (value.length() > configuration.getMaxValueLength()) {
                throw new JsonException(
                    JSON_THREAT_MAX_VALUE_LENGTH_KEY,
                    "Max length exceeded for field value [" + value + "] (max: " + configuration.getMaxValueLength() + ")"
                );
            }
        }
    }

    private void validateArray(JsonDepthCounter depthCounter, JsonParser parser) throws JsonException {
        JsonToken token;
        try {
            depthCounter.increment();
            validateDepth(depthCounter.getDepth());

            int entryCount = 0;
            while ((token = parser.nextToken()) != JsonToken.END_ARRAY) {
                validate(depthCounter, token, parser);

                entryCount += 1;
                if (configuration.hasMaxArraySize() && entryCount > configuration.getMaxArraySize()) {
                    throw new JsonException(
                        JSON_MAX_ARRAY_SIZE_KEY,
                        "Max entry count exceeded for array (max: " + configuration.getMaxArraySize()
                    );
                }
            }

            depthCounter.decrement();
        } catch (IOException e) {
            throw new JsonException(JSON_THREAT_DETECTED_KEY, "Invalid json array.", e);
        }
    }
}
