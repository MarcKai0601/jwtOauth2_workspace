package com.lanweihong.security.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.*;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * @author lanweihong 986310747@qq.com
 * @date 2021/1/13 16:47
 */
@Slf4j
@RestController
public class RefreshTokenController {

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Value("${security.oauth2.client.client-id}")
    private String clientId;

    @Value("${security.oauth2.client.client-secret}")
    private String clientSecret;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuthorizationServerTokenServices authorizationServerTokenServices;


    @Autowired
    private TokenStore tokenStore;

    private OAuth2Authentication createRefreshedAuthentication(OAuth2Authentication authentication, TokenRequest request) {
        Set<String> scope = request.getScope();
        OAuth2Request clientAuth = authentication.getOAuth2Request().refresh(request);
        if (scope != null && !scope.isEmpty()) {
            Set<String> originalScope = clientAuth.getScope();
            if (originalScope == null || !originalScope.containsAll(scope)) {
                throw new InvalidScopeException("Unable to narrow the scope of the client authentication to " + scope + ".", originalScope);
            }

            clientAuth = clientAuth.narrowScope(scope);
        }

        OAuth2Authentication narrowed = new OAuth2Authentication(clientAuth, authentication.getUserAuthentication());
        return narrowed;
    }
    private OAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication,Integer validitySeconds) {
            String value = UUID.randomUUID().toString();
            return (OAuth2RefreshToken)(validitySeconds > 0 ? new DefaultExpiringOAuth2RefreshToken(value, new Date(System.currentTimeMillis() + (long)validitySeconds * 1000L)) : new DefaultOAuth2RefreshToken(value));

    }

    @PostMapping("/oath/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication,@RequestParam Map<String, String> parameters) throws IOException {

        if (authentication  != null) {
            String grantType = "password";
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
            accessToken = authorizationServerTokenServices.getAccessToken(oAuth2Authentication);
            if (accessToken != null) {
                tokenStore.removeRefreshToken(accessToken.getRefreshToken());
                tokenStore.removeAccessToken(accessToken);
            }

        }

        response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString("logout"));

    }
        @PostMapping("/oath/refreshtoken")
    public void test(HttpServletRequest request, HttpServletResponse response, Authentication authentication,@RequestParam Map<String, String> parameters) throws IOException {
        if (authentication != null) {
            String refresh_token = parameters.get("refresh_token");
            String grantType = "refresh_token";
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
            Set<String> scope = clientDetails.getScope();
            Map<String, String> params = new HashMap<>();

            TokenRequest tokenRequest = new TokenRequest(params, clientId, scope, grantType);

            OAuth2AccessToken accessToken = null;
            DefaultTokenServices defualt = (DefaultTokenServices) authorizationServerTokenServices;
            //單一登入
        //    authorizationServerTokenServices.refreshAccessToken(refresh_token,tokenRequest);

            Integer validity = clientDetails.getRefreshTokenValiditySeconds();
            //  accessToken = defualt.refreshAccessToken(refresh_token,tokenRequest);

            OAuth2RefreshToken refreshToken = this.tokenStore.readRefreshToken(refresh_token);
            OAuth2Authentication myauthentication = this.tokenStore.readAuthenticationForRefreshToken(refreshToken);
            String clientId = myauthentication.getOAuth2Request().getClientId();
            if (clientId != null && clientId.equals(tokenRequest.getClientId())) {
                this.tokenStore.removeAccessTokenUsingRefreshToken(refreshToken);
                this.tokenStore.removeRefreshToken(refreshToken);
                accessToken = authorizationServerTokenServices.createAccessToken(myauthentication);
            }
            response.getWriter().write(objectMapper.writeValueAsString(accessToken));
        }
        response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json;charset=UTF-8");


    }


}
