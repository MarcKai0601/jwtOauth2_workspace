package com.lanweihong.security.auth.provider;

import com.lanweihong.security.auth.dto.UserDTO;
import com.lanweihong.security.auth.service.impl.UserDetailsServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * 登录校验逻辑
 * <p>
 * 第一步：行为认证，行为认证Token通过 -> 账号校验 -> 标识next=true，走安全认证，next=false，直接登录成功
 * 第二步：安全认证，安全认证Token通过 -> 登录成功
 * </p>
 */
@Slf4j
@Component
public class MyAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    //   if (true)
    //        throw new UsernameNotFoundException("username must not be null or empty");

     //   UsernamePasswordAuthenticationToken authenticationToken;
    //    authenticationToken = new UsernamePasswordAuthenticationToken();
        UserDTO user = new UserDTO();
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
                "[protected]",
                user.getAuthorities());

        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
         return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }


    /**
     * 是否新版本
     */
    private boolean isNewVersion(String version) {
        return version != null && version.startsWith("2.");
    }



}
