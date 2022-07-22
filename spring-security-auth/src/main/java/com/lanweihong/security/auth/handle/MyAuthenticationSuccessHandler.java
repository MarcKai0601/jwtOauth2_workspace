package com.lanweihong.security.auth.handle;


import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Set;

@Slf4j
@Component
public class MyAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuthorizationServerTokenServices authorizationServerTokenServices;

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private TokenStore tokenStore;

    @Value("${security.oauth2.client.client-id}")
    private String clientId;

    @Value("${security.oauth2.client.client-secret}")
    private String clientSecret;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String grantType = "password";

        // ((CredentialsContainer)authentication).eraseCredentials();
        // grantType = "refresh_token";

        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

        if (clientDetails == null) {
            throw new UnapprovedClientAuthenticationException("clientId对应的配置信息不存在:" + clientId);
        } else if (!StringUtils.equals(clientDetails.getClientSecret(), clientSecret)) {
            throw new UnapprovedClientAuthenticationException("clientSecret不匹配:" + clientId);
        }
        Set<String> scope = clientDetails.getScope();

        TokenRequest tokenRequest = new TokenRequest(new HashMap<>(), clientId, scope, grantType);
        OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);

        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, authentication);

        OAuth2AccessToken accessToken = null;

        accessToken = authorizationServerTokenServices.createAccessToken(oAuth2Authentication);


        response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(accessToken));




    }

    /**
     * 移除AccessToken，保证每次登陆都生成新的AccessToken，避免根据username拿到过时缓存
     */
    private void removeAccessToken(HttpServletRequest request) {

    }

    /**
     * 生成AccessToken
     */
//    private OAuth2AccessToken createAccessToken(Authentication authentication, String terminal, String brand) {
//        /*
//        String header = request.getHeader("Authorization");
//        String name = authentication.getName();
//        // String password = (String) authentication.getCredentials();
//        if (header == null || !header.startsWith("Basic ")) {
//            throw new UnapprovedClientAuthenticationException("请求头中无client信息");
//        }
//
//        String[] tokens = extractAndDecodeHeader(header, request);
//        assert tokens.length == 2;
//        String clientId = tokens[0];
//        String clientSecret = tokens[1];
//        */
//
//        // 验证client
//        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//
//
//
//        // 生成Token
//        TokenRequest tokenRequest = new TokenRequest(new HashMap<>(), clientId, scope, brand);
//
//
//        OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
//
//        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, authentication);
//
//        OAuth2AccessToken accessToken = authorizationServerTokenServices.createAccessToken(oAuth2Authentication);
//
//        return accessToken;
//    }

    /**
     * 移除AccessToken与userId的对应关系
     */
    private void removeAccessTokenUid(HttpServletRequest request) {

    }

    /**
     * 生成AccessToken与userId的对应关系
     */
    private void createAccessTokenUid(OAuth2AccessToken accessToken, Long userId) {

    }

    /**
     * 提取header中的client信息
     */
    private String[] extractAndDecodeHeader(String header, HttpServletRequest request) throws IOException {

        byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
        byte[] decoded;
        try {
            decoded = Base64.decode(base64Token);
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Failed to decode basic authentication token");
        }
        String token = new String(decoded, StandardCharsets.UTF_8);
        int delim = token.indexOf(":");
        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return new String[]{token.substring(0, delim), token.substring(delim + 1)};
    }

}
