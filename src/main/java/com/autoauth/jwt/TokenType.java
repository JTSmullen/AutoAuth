package com.autoauth.jwt;

public enum TokenType {

    ACCESS("access"),
    REFRESH("refresh"),
    TASK("task");

    private final String value;

    TokenType(String value){ this.value = value; }

    public String getValue() {
        return value;
    }

    public static TokenType fromString(String value) {
        for (TokenType type : values()) {
            if (type.value.equalsIgnoreCase(value)){
                return type;
            }
        }

        throw new IllegalArgumentException();
    }

}
