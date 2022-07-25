package com.lanweihong.security.auth.config;

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;

import java.util.ArrayList;
import java.util.List;

/**
 * 资源服务器配置
 * <p>
 * 参看：
 * https://github.com/spring-guides/tut-spring-security-and-angular-js/blob/master/oauth2-vanilla/README.adoc
 * https://github.com/jeesun/oauthserver
 * </p>
 */
@Configuration
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        // 自定义OAuth2返回的用户信息
        DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
        accessTokenConverter.setUserTokenConverter(new MyUserAuthenticationConverter());
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        //允许使用iframe 嵌套，避免swagger-ui 不被加载的问题
        http.headers().frameOptions().disable();

        // 受保护的资源
        List<String> matchers = new ArrayList<>();
        matchers.add("/oath/refreshtoken");
        matchers.add("/oath/logout");


        // 放行的资源
        List<String> ignores = new ArrayList<>();
        ignores.add("/oath/login");

        http.requestMatchers().antMatchers(matchers.toArray(new String[0]));

        // 放行的资源
        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry = http.authorizeRequests();

        ignores.forEach(url -> registry.antMatchers(url).permitAll());

        // 其他都需授权
        registry.anyRequest().fullyAuthenticated();
    }

}
