package com.autoauth.blacklist;

import java.time.Duration;

public interface TokenBlackList {

    void add (String jti, Duration TTL);

    boolean isBlackListed(String jti);

}
