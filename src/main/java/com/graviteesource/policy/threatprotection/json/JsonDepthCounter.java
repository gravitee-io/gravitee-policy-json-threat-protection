package com.graviteesource.policy.threatprotection.json;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JsonDepthCounter {

    private int depth = 0;

    public void increment() {
        depth++;
    }

    public void decrement() {
        depth--;
    }

    public int getDepth() {
        return depth;
    }
}
