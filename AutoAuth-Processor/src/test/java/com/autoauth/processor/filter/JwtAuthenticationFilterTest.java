package com.autoauth.processor.filter;

import com.autoauth.processor.jwt.JwtValidator;
import com.autoauth.processor.model.AutoAuthUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {

    private JwtValidator mockValidator;
    private JwtAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain mockFilterChain;

    @BeforeEach
    void setUp() {
        mockValidator = Mockito.mock(JwtValidator.class);
        filter = new JwtAuthenticationFilter(mockValidator);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        mockFilterChain = Mockito.mock(FilterChain.class);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldAuthenticateWhenValidTokenIsProvided() throws ServletException, IOException {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer valid-token-string");

        AutoAuthUser expectedUser = new AutoAuthUser("user123", List.of("admin"));
        when(mockValidator.validateAndExtractUser("valid-token-string")).thenReturn(expectedUser);

        filter.doFilter(request, response, mockFilterChain);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        AutoAuthUser principal = (AutoAuthUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        assertEquals("user123", principal.userId());

        verify(mockFilterChain).doFilter(request, response);
    }

    @Test
    void shouldNotAuthenticateWhenHeaderIsMissing() throws ServletException, IOException {
        filter.doFilter(request, response, mockFilterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(mockFilterChain).doFilter(request, response);
    }

    @Test
    void shouldNotAuthenticateWhenHeaderDoesNotStartWithBearer() throws ServletException, IOException {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Basic username:password");

        filter.doFilter(request, response, mockFilterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(mockFilterChain).doFilter(request, response);
    }

    @Test
    void shouldClearContextWhenTokenIsInvalid() throws ServletException, IOException {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer expired-token");
        when(mockValidator.validateAndExtractUser("expired-token"))
                .thenThrow(new IllegalArgumentException("Token expired"));
        filter.doFilter(request, response, mockFilterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(mockFilterChain).doFilter(request, response);
    }
}