package com.autoauth.processor.util;

import com.autoauth.processor.model.AutoAuthUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class AuthContext {
    
    public static Optional<AutoAuthUser> getCurrentUser() {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.getPrincipal() instanceof AutoAuthUser) {
            return Optional.of((AutoAuthUser) authentication.getPrincipal());
        }
        
        return Optional.empty();
        
    }
    
    public static String getCurrentUserId() {
        
        return getCurrentUser()
                .map(AutoAuthUser::userId)
                .orElse(null);
        
    }

    public static Object getCustomClaims(String claimKey) {
        return getCurrentUser()
                .map(user -> user.customClaims().get(claimKey))
                .orElse(null);
    }
    
}
