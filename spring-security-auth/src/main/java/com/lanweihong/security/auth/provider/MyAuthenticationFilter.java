package com.lanweihong.security.auth.provider;


import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <pre>
 * 重载UsernamePasswordAuthenticationFilter的attemptAuthentication,
 * obtainUsername,obtainPassword方法(完善逻辑) 增加验证码校验模块 添加验证码属性 添加验证码功能开关属性
 * </pre>
 */
@Slf4j
public class MyAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // 国际代码
    private static final String countryCodeParameter = "countryCode";

    // 登录终端
    private static final String terminalParameter = "terminal";

    // geetest token
    private static final String geetestTokenParameter = "geetestToken";

    // 明文密码
    private static final String plainPasswordParameter = "plainPassword";

    // 验证码字段
    private String validateCodeParameter = "validateCode";

    // 是否开启验证码功能
    private boolean openValidateCode = true;

    // post请求
    private boolean postOnly = true;


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        // 判断是不是post请求
        if (postOnly && !request.getMethod().equals(HttpMethod.POST.name())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        // 开启验证码功能的情况
        if (openValidateCode) {
            // 这里不验证，在MyAuthenticationProvider中处理
            // checkValidateCode(request);
        }

        // 获取Username和Password
       // String brand = SharedContainer.getThreadInstance().getBrand();
        String countryCode = obtainCountryCode(request);
        String username = obtainUsername(request);
        String password = obtainPassword(request);
        String plainPassword = obtainPlainPassword(request);
        String terminal = obtainTerminal(request);
       // String device = WebUtils.getDevice(request);
       // String ip = IpTools.getIpAddr(request);
        String version = request.getParameter("version");
        String cToken = request.getParameter("cToken");
        String vToken = request.getParameter("vToken");
        String vHash = request.getParameter("vHash");
        // 兼容v1
        String vCode = request.getParameter("vCode");
        // 兼容v1
        String geetestToken = obtainGeetestToken(request);
        // host
       // String host = WebUtils.getDomainName(request);
        // 是否信任此设备
        boolean trust = Boolean.parseBoolean(request.getParameter("trust"));

        // TODO 兼容老版，后续删除
        if (username == null) {
            username = request.getParameter("mobile");
        }

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        // 处理手机号开头的0
//        if (VerifyUtils.isPhone(username)) {
//            username = MaskUtils.getPhoneNoneZero(countryCode, username);
//        }

        username = username.trim();
//
//        if (vToken == null) {
//            log.info("登录请求：brand={}, username={}, ip={}, {}, version={}, terminal={}",
//                     brand,
//                     username,
//                     ip,
//                     host,
//                     version,
//                     terminal);
//        }

        // UsernamePasswordToken实现Authentication校验
//        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);
//        usernamePasswordToken.setCountryCode(countryCode);
//        usernamePasswordToken.setTerminal(terminal);
//        usernamePasswordToken.setDevice(device);
//        usernamePasswordToken.setTrust(trust);
//        usernamePasswordToken.setIp(ip);
//        usernamePasswordToken.setVHash(vHash);
//        usernamePasswordToken.setVCode(vCode);
//        usernamePasswordToken.setGeetestToken(geetestToken);
//        usernamePasswordToken.setVersion(version);
//        usernamePasswordToken.setCToken(cToken);
//        usernamePasswordToken.setVToken(vToken);
//        usernamePasswordToken.setPlainPassword(plainPassword);
//        usernamePasswordToken.setBrand(brand);

        // 允许子类设置详细属性


        // 运行UserDetailsService的loadUserByUsername 再次封装Authentication
        UsernamePasswordAuthenticationToken usernamePasswordToken = new UsernamePasswordAuthenticationToken(username, password);
        setDetails(request, usernamePasswordToken);
        return this.getAuthenticationManager().authenticate(usernamePasswordToken);
    }

    /**
     * 匹对验证码的正确性
     */
//    private void checkValidateCode(HttpServletRequest request) {
//        String validateCode = obtainValidateCodeParameter(request);
//        if ("".equals(validateCode)) {
//            throw new AuthenticationServiceException("请输入验证码");
//        }
//        if (request.getSession().getAttribute(ConstOAuth2.FORM_VERIFY_CODE_KEY) == null) {
//            throw new AuthenticationServiceException("验证码失效");
//        }
//        // 对比普通验证码
//        if (!request.getSession().getAttribute(ConstOAuth2.FORM_VERIFY_CODE_KEY).equals(validateCode)) {
//            throw new AuthenticationServiceException("验证码错误");
//        }
//    }

    /**
     * 获取验证码
     */
    private String obtainValidateCodeParameter(HttpServletRequest request) {
        return request.getParameter(validateCodeParameter);
    }

    /**
     * 设置验证码字段名
     */
    public void setValidateCodeParameter(String validateCode) {
        Assert.hasText(validateCode, "validateCode parameter must not be empty or null");
        this.validateCodeParameter = validateCode;
    }

    /**
     * 设置验证码校验开关
     */
    public void setOpenValidateCode(boolean openValidateCode) {
        this.openValidateCode = openValidateCode;
    }

    /**
     * 获取countryCode
     */
    private String obtainCountryCode(HttpServletRequest request) {
        return request.getParameter(countryCodeParameter);
    }

    /**
     * 获取terminal
     */
    private String obtainTerminal(HttpServletRequest request) {
        return request.getParameter(terminalParameter);
    }

    /**
     * 获取plainPassword
     */
    private String obtainPlainPassword(HttpServletRequest request) {
        return request.getParameter(plainPasswordParameter);
    }

    /**
     * 获取geetest验证token
     */
    private String obtainGeetestToken(HttpServletRequest request) {
        return request.getParameter(geetestTokenParameter);
    }

    /**
     * 设置请求方式
     */
    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    /**
     * 设置国际化工具
     */
//    public void setSpringMessage(SpringMessage springMessage) {
//        this.springMessage = springMessage;
//    }

}
