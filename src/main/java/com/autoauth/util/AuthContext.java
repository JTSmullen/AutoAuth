package com.autoauth.util;

import com.autoauth.model.AutoAuthUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Optional;

public class AuthContext {

    public static Optional<AutoAuthUser> getCurrentUser() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof AutoAuthUser) {
            return Optional.of((AutoAuthUser) authentication.getPrincipal());
        }

        return Optional.empty();

    }

    public static Optional<String> getCurrentUserId() {

        return getCurrentUser()
                .map(AutoAuthUser::userId);

    }

    public static Optional<List<String>> getCurrentUserRole(){
        return getCurrentUser()
                .map(AutoAuthUser::roles);
    }

    public static Optional<Object> getCustomClaims(String claimKey) {
        return getCurrentUser()
                .map(user -> user.customClaims().get(claimKey));
    }

}