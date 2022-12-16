package com.nellyxinwei.backend.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAthFilter extends OncePerRequestFilter {
  @Override
  protected void doFilterInternal(
    HttpServletRequest request,
    HttpServletResponse response,
    FilterChain filterChain) throws ServletException, IOException{
      final String authHeader = request.getHeader(AUTHORIZATION);
      final String userEmail;
      final String jwtToken;

      if(authHeader == null || !authHeader.startsWith("Bearer")){
        filterChain.doFilter(request,response);
        return;
      }

      jwtToken = authHeader.substring(7);
      
      userEmail = "something"; // TODO: To be implemented

      if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
        UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
        final boolean isTokenValid; // TODO: To be implemented
        if(isTokenValid){
          UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null)
        }
      }
    })
}
