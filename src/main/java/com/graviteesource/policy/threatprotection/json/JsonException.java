package com.graviteesource.policy.threatprotection.json;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JsonException extends Exception {

    private String key;

    public JsonException(String key, String message) {
        super(message);
        this.key = key;
    }

    public JsonException(String key, String message, Exception e) {
        super(message, e);
        this.key = key;
    }

    public String getKey() {
        return key;
    }
}
