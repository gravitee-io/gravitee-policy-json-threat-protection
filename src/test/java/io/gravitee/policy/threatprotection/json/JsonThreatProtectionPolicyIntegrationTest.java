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

import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import io.vertx.rxjava3.core.http.HttpClient;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@Slf4j
@ExtendWith(VertxExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class JsonThreatProtectionPolicyIntegrationTest {

    @Nested
    @GatewayTest
    @DeployApi({ "/apis/default.json" })
    class DefaultConfig extends AbstractJsonThreatProtectionPolicyIntegrationTest {

        @Test
        void should_accept_valid(HttpClient client, VertxTestContext context) {
            stubBackend(wiremock);

            var clientAsserts = send(client, """
            {
            "f": "a"
            }
            """);

            finalSuccessAssert(context, clientAsserts);
        }

        @Test
        void should_reject_duplicate_keys(HttpClient client, VertxTestContext context) {
            stubBackend(wiremock);

            var clientAsserts = send(client, """
            {
            "f": "a",
            "f": 12
            }
            """);

            rejectedAssert(context, clientAsserts);
        }

        @Test
        void should_reject_too_big_key(HttpClient client, VertxTestContext context) {
            stubBackend(wiremock);

            var clientAsserts = send(client, """
            {
            "foofoo": "a"
            }
            """);

            rejectedAssert(context, clientAsserts);
        }

        @Test
        void should_reject_too_big_value(HttpClient client, VertxTestContext context) {
            stubBackend(wiremock);

            var clientAsserts = send(client, """
            {
            "f": "abcdefg"
            }
            """);

            rejectedAssert(context, clientAsserts);
        }

        @Test
        void should_reject_too_big_array(HttpClient client, VertxTestContext context) {
            stubBackend(wiremock);

            var clientAsserts = send(client, """
            {
            "f": [1,2,3,4,5,6,7]
            }
            """);

            rejectedAssert(context, clientAsserts);
        }

        @Test
        void should_reject_too_much_entries(HttpClient client, VertxTestContext context) {
            stubBackend(wiremock);

            var clientAsserts = send(
                client,
                """
            {
            "f1": "a",
            "f2": "a",
            "f3": "a",
            "f4": "a",
            "f5": "a",
            "f6": "a"
            }
            """
            );

            rejectedAssert(context, clientAsserts);
        }

        @Test
        void should_reject_too_deep(HttpClient client, VertxTestContext context) {
            stubBackend(wiremock);

            var clientAsserts = send(client, """
            {"f1": {"f2": {"f3": {"f4": {"f5": {"f6": 1}}}}}}
            """);

            rejectedAssert(context, clientAsserts);
        }
    }

    @Nested
    @GatewayTest
    @DeployApi({ "/apis/default-accept-duplicate-keys.json" })
    class AcceptDuplicateKeys extends AbstractJsonThreatProtectionPolicyIntegrationTest {

        @Test
        void should_accept_duplicate_keys(HttpClient client, VertxTestContext context) {
            stubBackend(wiremock);

            var clientAsserts = send(client, """
            {
            "f": "a",
            "f": 12
            }
            """);

            finalSuccessAssert(context, clientAsserts);
        }
    }
}
