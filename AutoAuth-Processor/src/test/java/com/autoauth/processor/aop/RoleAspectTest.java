package com.autoauth.processor.aop;

import com.autoauth.processor.annotation.RequiresRole;
import com.autoauth.processor.model.AutoAuthUser;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Method;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class RoleAspectTest {

    private RoleAspect roleAspect;
    private JoinPoint mockJoinPoint;
    private MethodSignature mockSignature;

    @BeforeEach
    void setUp() {
        roleAspect = new RoleAspect();
        mockJoinPoint = Mockito.mock(JoinPoint.class);
        mockSignature = Mockito.mock(MethodSignature.class);

        when(mockJoinPoint.getSignature()).thenReturn(mockSignature);

        TestControllerStub target = new TestControllerStub();
        when(mockJoinPoint.getTarget()).thenReturn(target);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldAllowAccessWhenUserHasRequiredRole() throws NoSuchMethodException {
        setCurrentUser("user1", List.of("admin"));

        Method adminMethod = TestControllerStub.class.getMethod("adminOnly");
        when(mockSignature.getMethod()).thenReturn(adminMethod);

        assertDoesNotThrow(() -> roleAspect.checkRoles(mockJoinPoint));
    }

    @Test
    void shouldDenyAccessWhenUserLacksRequiredRole() throws NoSuchMethodException {
        setCurrentUser("user2", List.of("user"));

        Method adminMethod = TestControllerStub.class.getMethod("adminOnly");
        when(mockSignature.getMethod()).thenReturn(adminMethod);

        assertThrows(AccessDeniedException.class, () ->
                roleAspect.checkRoles(mockJoinPoint)
        );
    }

    @Test
    void shouldAllowAccessWhenUserHasAtLeastOneRequiredRole() throws NoSuchMethodException {
        setCurrentUser("user3", List.of("premium"));

        Method multiRoleMethod = TestControllerStub.class.getMethod("multiRoleMethod");
        when(mockSignature.getMethod()).thenReturn(multiRoleMethod);

        assertDoesNotThrow(() -> roleAspect.checkRoles(mockJoinPoint));
    }

    private void setCurrentUser(String userId, List<String> roles) {
        AutoAuthUser user = new AutoAuthUser(userId, roles);
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(user, null, List.of());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    static class TestControllerStub {

        @RequiresRole("admin")
        public void adminOnly() {}

        @RequiresRole({"admin", "premium"})
        public void multiRoleMethod() {}
    }
}