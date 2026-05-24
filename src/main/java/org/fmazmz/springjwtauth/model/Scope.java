package org.fmazmz.springjwtauth.model;

import lombok.Getter;

import java.util.Arrays;
import java.util.List;

public enum Scope {
    PROFILE_READ("profile:read"),
    PROFILE_WRITE("profile:write"),
    USER_READ("user:read"),
    USER_WRITE("user:write");

    @Getter
    private final String value;

    Scope(String label) {
        this.value = label;
    }

    public static List<String> forRole(Role role) {
        return switch (role) {
            case USER -> List.of(PROFILE_READ.value, PROFILE_WRITE.value);
            case ADMIN -> Arrays.stream(values()).map(Scope::getValue).toList();
        };
    }
}
