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

import static io.gravitee.policy.threatprotection.json.JsonThreatProtectionPolicy.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.SimpleReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
@ExtendWith(MockitoExtension.class)
public class JsonThreatProtectionPolicyTest {

    @Mock
    private Request request;

    @Mock
    private Response response;

    @Mock
    private PolicyChain policyChain;

    @Captor
    private ArgumentCaptor<PolicyResult> resultCaptor;

    private static final String JSON =
        """
        {
            "travel": {
                "type": "TOURISM",
                "language": "FR",
                "isPolicyHolderTravelling": true,
                "start": "2019-06-03",
                "end": "2019-06-05"
            },
            "policyHolder": {
                "civility": "xxxxxx",
                "firstname": "xxxxxx",
                "lastname": "xxxxxx",
                "maidenname": "xxxxxx",
                "id": "45465",
                "phone": "0606060607",
                "professionalPhone": "0101010101",
                "email": "xxxxxxxxxxx",
                "address": {
                    "street": "my street",
                    "zipcode": "xxxxxx",
                    "city": "xxxxxx",
                    "countryCode": "xxxxxx"
                }
            },
            "beneficiaries": [
                {
                    "civility": "xxxx",
                    "firstname": "xxxxx",
                    "lastname": "xxxxx",
                    "maidenname": "xxxxxxx",
                    "relationtopolicyholder": "xxxxxxx"
                },
                {
                    "civility": "xxxx",
                    "firstname": "xxxxx",
                    "lastname": "xxxxx",
                    "maidenname": "xxxxxxx",
                    "relationtopolicyholder": "xxxxxxx"
                },
                {
                    "civility": "xxxx",
                    "firstname": "xxxxx",
                    "lastname": "xxxxx",
                    "maidenname": "xxxxxxx",
                    "relationtopolicyholder": "xxxxxxx"
                },
                {
                    "civility": "xxxx",
                    "firstname": "xxxxx",
                    "lastname": "xxxxx",
                    "maidenname": "xxxxxxx",
                    "relationtopolicyholder": "xxxxxxx"
                },
                {
                    "civility": "xxxx",
                    "firstname": "xxxxx",
                    "lastname": "xxxxx",
                    "maidenname": "xxxxxxx",
                    "relationtopolicyholder": "xxxxxxx"
                },
                {
                    "civility": "xxxx",
                    "firstname": "xxxxx",
                    "lastname": "xxxxx",
                    "maidenname": "xxxxxxx",
                    "relationtopolicyholder": "xxxxxxx"
                }
            ]
        }""";

    JsonThreatProtectionPolicyConfiguration configuration;

    private JsonThreatProtectionPolicy cut;

    @BeforeEach
    public void before() {
        configuration = new JsonThreatProtectionPolicyConfiguration();
        configuration.setMaxArraySize(100);
        configuration.setMaxDepth(1000);
        configuration.setMaxEntries(100);
        configuration.setMaxNameLength(100);
        configuration.setMaxValueLength(100);

        cut = new JsonThreatProtectionPolicy(configuration);

        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.CONTENT_TYPE, MediaType.APPLICATION_JSON);
        when(request.headers()).thenReturn(httpHeaders);
    }

    @Test
    public void should_accept_all_when_content_type_is_not_json() {
        Mockito.reset(request);
        when(request.headers()).thenReturn(HttpHeaders.create());
        ReadWriteStream<?> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNull();
    }

    @Test
    public void should_accept_valid_json() {
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();

        readWriteStream.write(Buffer.buffer("{ \"valid\": true, \"array\": [ 1, 2, 3 ], \"container\": { \"a\": true } }"));
        readWriteStream.end();

        verifyNoInteractions(policyChain);
    }

    @Test
    public void should_reject_invalid_json() {
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();

        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("Invalid"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(resultCaptor.capture());
        assertThat(resultCaptor.getValue().key()).isEqualTo(JSON_THREAT_DETECTED_KEY);
    }

    @Test
    public void should_reject_when_max_name_length_exceeded() {
        configuration.setMaxNameLength(4);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();

        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("{ \"valid\": true, \"array\": [ 1, 2, 3 ], \"container\": { \"a\": \"123456789\" } }"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(resultCaptor.capture());
        assertThat(resultCaptor.getValue().key()).isEqualTo(JSON_THREAT_MAX_NAME_LENGTH_KEY);
    }

    @Test
    public void should_reject_when_max_value_length_exceeded() {
        configuration.setMaxValueLength(8);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("{ \"valid\": false, \"array\": [ 1, 2, 3 ], \"container\": { \"a\": \"123456789\" } }"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(resultCaptor.capture());
        assertThat(resultCaptor.getValue().key()).isEqualTo(JSON_THREAT_MAX_VALUE_LENGTH_KEY);
    }

    @Test
    public void should_reject_when_max_object_entries_exceeded() {
        configuration.setMaxEntries(2);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("{ \"valid\": false, \"array\": [ 1, 2, 3 ], \"container\": { \"a\": \"123456789\" } }"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(resultCaptor.capture());
        assertThat(resultCaptor.getValue().key()).isEqualTo(JSON_THREAT_MAX_ENTRIES_KEY);
    }

    @Nested
    class ArraySizeProtection {

        @Test
        public void should_reject_when_max_array_size_exceeded() {
            configuration.setMaxArraySize(2);
            ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

            assertThat(readWriteStream).isNotNull();
            final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

            readWriteStream.write(Buffer.buffer("{ \"valid\": false, \"array\": [ 1, 2, 3 ], \"container\": { \"a\": \"123456789\" } }"));
            readWriteStream.end();

            assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

            verify(policyChain, times(1)).streamFailWith(resultCaptor.capture());
            assertThat(resultCaptor.getValue().key()).isEqualTo(JSON_MAX_ARRAY_SIZE_KEY);
        }

        @Test
        public void should_reject_when_max_array_of_object_size_exceeded() {
            configuration.setMaxArraySize(2);
            ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

            assertThat(readWriteStream).isNotNull();
            final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

            readWriteStream.write(Buffer.buffer(JSON));
            readWriteStream.end();

            assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

            verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
        }

        @Test
        public void should_reject_when_max_array_size_exceeded_in_sub_array() {
            configuration.setMaxArraySize(4);
            ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

            assertThat(readWriteStream).isNotNull();
            final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

            readWriteStream.write(Buffer.buffer("{\"a\":[\"1\",\"2\",\"3\",[\"1\",\"2\",\"3\",[\"1\",\"2\",\"3\",\"4\",\"5\"]]]}"));
            readWriteStream.end();

            assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

            verify(policyChain, times(1)).streamFailWith(resultCaptor.capture());
            assertThat(resultCaptor.getValue().key()).isEqualTo(JSON_MAX_ARRAY_SIZE_KEY);
        }

        @Test
        public void should_accept_when_max_array_size_does_not_exceed() {
            configuration.setMaxArraySize(4);
            ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

            assertThat(readWriteStream).isNotNull();
            final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

            readWriteStream.write(Buffer.buffer("{\"a\":[\"1\",\"2\",\"3\",[\"1\",\"2\",\"3\",[\"1\",\"2\",\"3\",\"4\"]]]}"));
            readWriteStream.end();

            assertThat(hasCalledEndOnReadWriteStreamParentClass).isTrue();

            verifyNoInteractions(policyChain);
        }
    }

    @Nested
    class DepthProtection {

        @Test
        public void should_reject_when_max_depth_exceeded() {
            configuration.setMaxDepth(1);
            ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

            assertThat(readWriteStream).isNotNull();
            final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

            readWriteStream.write(Buffer.buffer("{ \"valid\": false, \"array\": [ 1, 2, 3 ], \"container\": { \"a\": \"123456789\" } }"));
            readWriteStream.end();

            assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

            verify(policyChain, times(1)).streamFailWith(resultCaptor.capture());
            assertThat(resultCaptor.getValue().key()).isEqualTo(JSON_THREAT_MAX_DEPTH_KEY);
        }

        @Test
        public void should_reject_when_max_depth_in_arrays_exceeded() {
            configuration.setMaxDepth(6);
            ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

            assertThat(readWriteStream).isNotNull();
            final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

            readWriteStream.write(
                Buffer.buffer("{ \"valid\": false, \"array\": [ 1, 2, 3 ], \"container\": { \"a\": [ [ [ [ [ \"123456789\" ] ] ] ] ] } }")
            );
            readWriteStream.end();

            assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

            verify(policyChain, times(1)).streamFailWith(resultCaptor.capture());
            assertThat(resultCaptor.getValue().key()).isEqualTo(JSON_THREAT_MAX_DEPTH_KEY);
        }

        @Test
        public void should_accept_when_max_depth_in_arrays_does_not_exceed() {
            configuration.setMaxDepth(7);
            ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

            assertThat(readWriteStream).isNotNull();
            final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

            readWriteStream.write(
                Buffer.buffer("{ \"valid\": false, \"array\": [ 1, 2, 3 ], \"container\": { \"a\": [ [ [ [ [ \"123456789\" ] ] ] ] ] } }")
            );
            readWriteStream.end();

            assertThat(hasCalledEndOnReadWriteStreamParentClass).isTrue();

            verifyNoInteractions(policyChain);
        }
    }

    @Nested
    class DuplicateKeyBehavior {

        @Test
        public void should_reject_when_duplicate_key() {
            ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

            assertThat(readWriteStream).isNotNull();
            final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

            String e =
                """
                {
                    "travel": {
                        "type": "TOURISM"
                    },
                    "travel": 12,
                }
                """;

            readWriteStream.write(Buffer.buffer(e));
            readWriteStream.end();

            assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

            verify(policyChain, times(1)).streamFailWith(resultCaptor.capture());
            assertThat(resultCaptor.getValue().key()).isEqualTo(JSON_THREAT_DETECTED_KEY);
        }

        @Test
        public void should_accept_when_duplicate_key() {
            configuration.setPreventDuplicateKey(false);
            cut = new JsonThreatProtectionPolicy(configuration);
            ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

            assertThat(readWriteStream).isNotNull();
            final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

            String e =
                """
                {
                    "travel": {
                        "type": "TOURISM"
                    },
                    "travel": 12
                }
                """;

            readWriteStream.write(Buffer.buffer(e));
            readWriteStream.end();

            assertThat(hasCalledEndOnReadWriteStreamParentClass).isTrue();

            verifyNoInteractions(policyChain);
        }
    }

    /**
     * Replace the endHandler of the resulting ReadWriteStream of the policy execution.
     * This endHandler will set an {@link AtomicBoolean} to {@code true} if its called.
     * It will allow us to verify if super.end() has been called on {@link BufferedReadWriteStream#end()}
     * @param readWriteStream: the {@link ReadWriteStream} to modify
     * @return an AtomicBoolean set to {@code true} if {@link SimpleReadWriteStream#end()}, else {@code false}
     */
    private AtomicBoolean spyEndHandler(ReadWriteStream<Buffer> readWriteStream) {
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = new AtomicBoolean(false);
        readWriteStream.endHandler(__ -> hasCalledEndOnReadWriteStreamParentClass.set(true));
        return hasCalledEndOnReadWriteStreamParentClass;
    }
}
