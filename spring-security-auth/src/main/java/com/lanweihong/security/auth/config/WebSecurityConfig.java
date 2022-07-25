package com.lanweihong.security.auth.config;

import com.lanweihong.security.auth.handle.MyAuthenctiationFailureHandler;
import com.lanweihong.security.auth.handle.MyAuthenticationSuccessHandler;
import com.lanweihong.security.auth.handle.MyLogoutSuccessHandler;
import com.lanweihong.security.auth.provider.MyAuthenticationFilter;
import com.lanweihong.security.auth.provider.MyAuthenticationProvider;
import com.lanweihong.security.auth.service.impl.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 *
 * @author lanweihong 986310747@qq.com
 * @date 2021/1/13 02:55
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationProvider authProvider;

    @Autowired
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Autowired
    private MyAuthenctiationFailureHandler myAuthenctiationFailureHandler;

    @Autowired
    private MyLogoutSuccessHandler myLogoutSuccessHandler;
//
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthorizationServerEndpointsConfiguration endpoints;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        MyAuthenticationFilter au = new MyAuthenticationFilter();
        au.setAuthenticationManager(this.authenticationManager());
        au.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/oath/login", "POST"));
        au.setAuthenticationSuccessHandler(myAuthenticationSuccessHandler); // 必须现在这里注入，否则Handler中无法注入实例
        au.setAuthenticationFailureHandler(myAuthenctiationFailureHandler); // 必须现在这里注入，否则Handler中无法注入实例

        http
                // 支持跨域请求
                .cors()

                .and()
                // 禁用 CSRF
                .csrf().disable()

                .formLogin().disable()
                .httpBasic().disable()
              //  .logout()
             //   .logoutUrl("/oath/logout")
             //   .logoutSuccessHandler(myLogoutSuccessHandler)
             //   .and()
                .authorizeRequests()
                .antMatchers("/oath/refreshtoken").authenticated()
                .antMatchers("/oath/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .authenticationProvider(authProvider).addFilterAt(au, UsernamePasswordAuthenticationFilter.class);

    }

    /**
     * 重写 authenticationManagerBean()
     * @return
     * @throws Exception
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService);
//    }

}
