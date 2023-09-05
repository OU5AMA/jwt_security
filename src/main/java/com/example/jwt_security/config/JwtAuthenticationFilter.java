package com.example.jwt_security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component // Make a spring bean/ a managed bean
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authentication = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
    if(authentication == null || !authentication.startsWith("Bearer ")){
        filterChain.doFilter(request, response);
        return;
    }
    jwt = authentication.substring(7);
    userEmail = jwtService.extractUserName(jwt);
    if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
        UserDetails userDetails = this.UserDetailService.loadUserByName(userEmail);
        if(jwtService.isTokenValid(jwt, userDetails)){
//            if the token is valid, we need to update the security context and send the request to the dispatcher servlet
//            create an object of type userNamePasswordAuthenticationToken
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
//            give it some more details
            authenticationToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );
        }
    }
    }
}
