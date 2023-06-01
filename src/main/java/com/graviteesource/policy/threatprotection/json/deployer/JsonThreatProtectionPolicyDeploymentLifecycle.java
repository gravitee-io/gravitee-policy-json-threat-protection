package com.graviteesource.policy.threatprotection.json.deployer;

import io.gravitee.node.api.deployer.AbstractPluginDeploymentLifecycle;

/**
 * @author Kamiel Ahmadpour (kamiel.ahmadpour at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JsonThreatProtectionPolicyDeploymentLifecycle extends AbstractPluginDeploymentLifecycle {

    private static final String POLICY_JSON_THREAT_PROTECTION = "json-threat-protection";

    @Override
    protected String getFeatureName() {
        return POLICY_JSON_THREAT_PROTECTION;
    }
}
