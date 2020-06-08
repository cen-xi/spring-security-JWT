package com.example.securityjwt5605.config;


import com.example.securityjwt5605.filters.JwtFilter;
import com.example.securityjwt5605.filters.JwtLoginFilter;
import com.example.securityjwt5605.filters.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.lang.reflect.Method;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserDetailsService myUserDetailsService;


    /**
     * 全局的跨域配置
     */
    @Bean
    public WebMvcConfigurer WebMvcConfigurer() {
        return new WebMvcConfigurer() {
            public void addCorsMappings(CorsRegistry corsRegistry) {
                //仅仅让/login可以跨域
                corsRegistry.addMapping("/login").allowCredentials(true).allowedHeaders("*");
                //仅仅让/logout可以跨域
                corsRegistry.addMapping("/logout").allowCredentials(true).allowedHeaders("*");
                //允许所有接口可以跨域访问
                //corsRegistry.addMapping("/**").allowCredentials(true).allowedHeaders("*");

            }
        };

    }

    /**
     * 忽略过滤的静态文件路径
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers(
                        "/js/**/*.js",
                        "/css/**/*.css",
                        "/img/**",
                        "/html/**/*.html"
                );
    }


    //内存放入可登录的用户信息
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        System.out.println("===============================认证管理构造器==================================");

        //直接注册信息到内存，会导致jrebel热更新失效，无法更新该内容
        //
        //如果仅仅设置了roles,则权限自动设置并自动添加前缀 为 ROLE_【角色内部的字符串，可以设置多个】，
        //字符串不可再添加ROLE_，会报java.lang.IllegalArgumentException: ROLE_user cannot start with ROLE_ (it is automatically added)
        //意思是用 ROLE_前缀会自动添加，
//         auth.inMemoryAuthentication().withUser("cen")
//                 .password("$2a$10$Qghi7vHdyQJHYlAO.FCo/u3gCbqwWBVaSHjIF0Vci.C5.1l71SExq").roles("user")
//                //如果使用了roles 和 authorities ，那么roles将失效，将会注册authorities内部的字符串为权限，且不会添加前缀名ROLE_
//                .and().withUser("admin")
//                 .password("$2a$10$ywq3gn6E15tnY3URptsIz.zn/fznWGqc2VhO4zphS/sIbWZJtLCVK").roles("user").authorities("ROLE_admin");
//            //
        //因此用户cen的权限为ROLE_user
        //用户admin的权限为 admin

        //
        //
        //调用数据库层，根据用户名获取用户信息回来，
        auth.userDetailsService(myUserDetailsService)
                //设置加密方式
                .passwordEncoder(passwordEncoder());

    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //过滤规则,一旦设置了重写了这个方法，必须设置登录配置
    //在启动的时候就执行了
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println("===============================过滤规则==================================");

        http.authorizeRequests()
                .antMatchers("/hello").hasRole("user")
                .antMatchers("/admin").hasRole("admin")
//                .antMatchers("/admin").hasAuthority("admin")
                //当访问/login的请求方式是post才允许通过
                .antMatchers(HttpMethod.POST, "/login").permitAll()
//                .anyRequest()
                .anyRequest().authenticated()
                .and()
                //首次登录拦截。仅允许post访问/login
                .addFilterBefore(new JwtLoginFilter("/login", authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                //token验证拦截
                .addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class)
                //
                .cors()
                .and()
                .csrf().disable();
        //
        //使用jwt[java web token],做登录校验，则该设置失效，因为没有使用session做为登录控制
//        http.sessionManagement().maximumSessions(1);


    }


}
