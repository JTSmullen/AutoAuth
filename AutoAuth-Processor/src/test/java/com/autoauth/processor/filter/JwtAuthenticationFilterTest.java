package com.autoauth.processor.filter;

import com.autoauth.processor.jwt.JwtValidator;
import com.autoauth.processor.model.AutoAuthUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import jakarta.servlet.http.Cookie;
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

    private static final String COOKIE_NAME = "my_token";

    @BeforeEach
    void setUp() {
        mockValidator = Mockito.mock(JwtValidator.class);
        filter = new JwtAuthenticationFilter(mockValidator, COOKIE_NAME);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        mockFilterChain = Mockito.mock(FilterChain.class);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // Import this at the top of your test file:
    // import jakarta.servlet.http.Cookie;

    @Test
    void shouldAuthenticateWhenValidTokenIsProvidedInCookie() throws ServletException, IOException {
        // Given: The filter is configured to look for "my_token"
        filter = new JwtAuthenticationFilter(mockValidator, "my_token");

        // Request contains a cookie with the correct name and token
        request.setCookies(new Cookie("my_token", "valid-cookie-token"));

        AutoAuthUser expectedUser = new AutoAuthUser("user123", List.of("admin"), null);
        when(mockValidator.validateAndExtractUser("valid-cookie-token")).thenReturn(expectedUser);

        // When
        filter.doFilter(request, response, mockFilterChain);

        // Then: User should be successfully authenticated
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        AutoAuthUser principal = (AutoAuthUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        assertEquals("user123", principal.userId());
        verify(mockFilterChain).doFilter(request, response);
    }

    @Test
    void shouldPreferHeaderOverCookieWhenBothArePresent() throws ServletException, IOException {
        filter = new JwtAuthenticationFilter(mockValidator, "my_token");

        // Request has BOTH a header and a cookie
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer header-token");
        request.setCookies(new Cookie("my_token", "cookie-token"));

        // Only the header token should be validated
        AutoAuthUser expectedUser = new AutoAuthUser("user_header", List.of("user"), null);
        when(mockValidator.validateAndExtractUser("header-token")).thenReturn(expectedUser);

        // When
        filter.doFilter(request, response, mockFilterChain);

        // Then: Authenticated user should match the header token, NOT the cookie token
        AutoAuthUser principal = (AutoAuthUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        assertEquals("user_header", principal.userId());
        verify(mockFilterChain).doFilter(request, response);
    }

    @Test
    void shouldAuthenticateWhenValidTokenIsProvided() throws ServletException, IOException {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer valid-token-string");

        AutoAuthUser expectedUser = new AutoAuthUser("user123", List.of("admin"), null);
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