package com.autoauth.aop;

import com.autoauth.annotation.RequiresRole;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.util.AuthContext;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.access.AccessDeniedException;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

/**
 * Aspect that intercepts methods or classes annotated with {@link RequiresRole}
 * Resolves the calling user's roles and checks if they have access with {@link #validateRoles(RequiresRole)}
 */
@Aspect
public class RoleAspect {

    /**
     * If the Endpoint has {@code @RequiresRole} annotation we check the request to see if
     * the user has the required minimum role to hit that endpoint.
     *
     * @param joinPoint metadata of the intercepted method
     */
    @Before("@within(com.autoauth.annotation.RequiresRole) " +
            "|| @annotation(com.autoauth.annotation.RequiresRole)")
    public void checkRoles(JoinPoint joinPoint) {

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // fetch the spring bean instance
        Class<?> targetClass = joinPoint.getTarget().getClass();

        RequiresRole annotation = AnnotatedElementUtils.findMergedAnnotation(method, RequiresRole.class);

        if(annotation == null) {
            annotation = AnnotatedElementUtils.findMergedAnnotation(targetClass, RequiresRole.class);
        }

        if (annotation != null) {
            // pass the context of user and method to the role checker
            validateRoles(annotation);
        }

    }

    /**
     * enforces the RBAC by checking to see if you have at least the minimum role to
     * hit said endpoint.
     *
     * @param requiresRole method metadata that has RBAC to check
     */
    private void validateRoles(RequiresRole requiresRole) {

        List<String> userRoles = AuthContext.getCurrentUser()
                .map(AutoAuthUser::roles)
                .orElse(List.of());

        List<String> requiredRoles = Arrays.asList(requiresRole.value());

        // start with 0 trust
        boolean hasAccess = false;

        // if you have role or higher role return true and let traffic through
        if (requiresRole.requireAll()) {
            hasAccess = new HashSet<>(userRoles).containsAll(requiredRoles);
        } else {
            for (String role : requiredRoles) {
                if (userRoles.contains(role)) {
                    hasAccess = true;
                    break;
                }
            }
        }

        // if not access is found throw 403 http code
        if (!hasAccess) {
            throw new AccessDeniedException("Access Denied: User lacks required role");
        }

    }

}