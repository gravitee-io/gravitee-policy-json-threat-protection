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

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.connector.EndpointBuilder;
import io.gravitee.apim.gateway.tests.sdk.connector.EntrypointBuilder;
import io.gravitee.plugin.endpoint.EndpointConnectorPlugin;
import io.gravitee.plugin.endpoint.http.proxy.HttpProxyEndpointConnectorFactory;
import io.gravitee.plugin.entrypoint.EntrypointConnectorPlugin;
import io.gravitee.plugin.entrypoint.http.proxy.HttpProxyEntrypointConnectorFactory;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.http.HttpMethod;
import io.vertx.junit5.VertxTestContext;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientResponse;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AbstractJsonThreatProtectionPolicyIntegrationTest
    extends AbstractPolicyTest<JsonThreatProtectionPolicy, JsonThreatProtectionPolicyConfiguration> {

    @Override
    public void configureEntrypoints(Map<String, EntrypointConnectorPlugin<?, ?>> entrypoints) {
        entrypoints.putIfAbsent("http-proxy", EntrypointBuilder.build("http-proxy", HttpProxyEntrypointConnectorFactory.class));
    }

    @Override
    public void configureEndpoints(Map<String, EndpointConnectorPlugin<?, ?>> endpoints) {
        endpoints.putIfAbsent("http-proxy", EndpointBuilder.build("http-proxy", HttpProxyEndpointConnectorFactory.class));
    }

    protected void stubBackend(WireMockServer wiremock) {
        wiremock.stubFor(
            WireMock
                .post("/mock")
                .willReturn(WireMock.jsonResponse("""
                {"message": "Response from mock"}
                """, 200))
        );
    }

    protected Single<HttpClientResponse> send(HttpClient client, String body) {
        return client.rxRequest(HttpMethod.POST, "/mock").flatMap(e -> e.putHeader("Content-Type", "application/json").rxSend(body));
    }

    protected static void finalSuccessAssert(VertxTestContext context, Single<HttpClientResponse> clientAsserts) {
        clientAsserts.subscribe(
            e -> {
                if (200 <= e.statusCode() && e.statusCode() < 300) {
                    context.completeNow();
                } else {
                    context.failNow(new Exception("Unexpected status code: " + e.statusCode()));
                }
            },
            context::failNow
        );
    }

    protected static void rejectedAssert(VertxTestContext context, Single<HttpClientResponse> clientAsserts) {
        clientAsserts.subscribe(
            e -> {
                if (400 == e.statusCode()) {
                    context.completeNow();
                } else {
                    context.failNow(new Exception("Unexpected rejected with 400 but was : " + e.statusCode()));
                }
            },
            context::failNow
        );
    }
}
