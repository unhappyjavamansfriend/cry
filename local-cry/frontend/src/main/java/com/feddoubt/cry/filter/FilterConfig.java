package com.feddoubt.cry.filter;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

//Filter 是被容器重新初始化
@Configuration
public class FilterConfig {

    // 配置和注册自定义过滤器，用于拦截和处理特定路径的请求
    @Bean
    public FilterRegistrationBean<ServiceFilter> userTrackingFilter(ServiceFilter filter) {
        FilterRegistrationBean<ServiceFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
//        registrationBean.setFilter(new ServiceFilter(jwtProvider));
        registrationBean.addUrlPatterns("/api/v1/cry/**");
        registrationBean.setOrder(1);
        return registrationBean;
    }
}