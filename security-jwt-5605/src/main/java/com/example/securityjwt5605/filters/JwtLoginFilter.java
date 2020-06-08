package com.example.securityjwt5605.filters;

import com.example.securityjwt5605.model.JwtUser;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 首次登录才调用这个方法
 */

public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {
    //构造方法 ，记得使用 public
    //第一个是 登录路径 。第二个是 认证管理者
    //在启动的时候就已经h已经执行了
    public JwtLoginFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(defaultFilterProcessesUrl));
        System.out.println("===============================登录拦截1==================================");
        //存储到父类，可不加 super.便于方法 attemptAuthentication（）调用,
        setAuthenticationManager(authenticationManager);

    }


    /**
     *访问/login登录后首先进入这里
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse resp) throws AuthenticationException, IOException, ServletException {
        JwtUser user = new JwtUser();
        System.out.println("===============================登录拦截2==================================");
        try {
            //从请求中获取用户验证信息
            //将json字符串解析
             user = new ObjectMapper().readValue(req.getInputStream(), JwtUser.class);
//        }catch (Exception ignored){
//            //Exception ignored表示忽略异常
//            //这样内部可以不写内容
//        }
//            String username = req.getParameter("username");
//            String password = req.getParameter("password");
//            if (username == null || password == null){
//                throw new Exception();
//            }
//            user.setUsername(username);
//            user.setPassword(password);
        }catch (Exception e){
            //Exception ignored表示忽略异常
            System.out.println("请求无法解析出JwtUser对象");

        }
        //对请求做认证操作，如何校验，由默认的程序完成，不涉及对比操作，因为用户信息存在内存中，否则需要修改 securityConfig.java 的 configure(AuthenticationManagerBuilder auth) 用于设置数据库操作
        //认证管理对象执行认证方法，new 一个用户密码认证令牌对象，参数为用户名和密码，然后放入认证方法中
        //然后执行登录验证
        return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));


    }


    //认证成功
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("===============================登录拦截3==================================");
        //获取登录角色的权限
        //这是权限 ，如果登录内存只有角色配置，无权限配置，则自动添加前缀构成权限 ROLE_角色
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        //线程安全
        StringBuffer stringBuffer = new StringBuffer();
        for (GrantedAuthority grantedAuthority : authorities) {
            System.out.println("当前有的权限："+grantedAuthority);
            //用逗号隔开好一点，不然后面需要手动切割
            stringBuffer.append(grantedAuthority.getAuthority()).append(",");
        }
        //生成令牌 token
        String jwt = Jwts.builder()
                //登录角色的权限，这会导致如果权限更改，该token无法及时更新权限信息
                .claim("authorities", stringBuffer)
                //用户名
                .setSubject(authResult.getName())
                //存活时间，过期则判为无效
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                //签名,第一个参数时算法，第二个参数时内容，内容可随意写
                .signWith(SignatureAlgorithm.HS512, "java521@java")
                //协议完成
                .compact();
        System.out.println(jwt);
        System.out.println("======================");
        System.out.println(stringBuffer);
        //设置json数据返回给前端
        Map<String, Object> map = new HashMap<>();
        map.put("token", jwt);
        map.put("msg", "登录成功");
        //MediaType.APPLICATION_JSON_UTF8_VALUE 等用于  "application/json;charset=UTF-8"
//        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.setContentType("application/json;charset=utf-8");
        PrintWriter printWriter = response.getWriter();
        //转成json后传送
        printWriter.write(new ObjectMapper().writeValueAsString(map));
        //关闭流
        printWriter.flush();
        printWriter.close();

    }

    //认证失败
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        System.out.println("===============================登录拦截4==================================");
        Map<String, Object> map = new HashMap<>();
        map.put("msg", "登录失败");
        response.setContentType("application/json;charset=utf-8");
        PrintWriter printWriter = response.getWriter();
        //转成json后传送
        printWriter.write(new ObjectMapper().writeValueAsString(map));
        //关闭流
        printWriter.flush();
        printWriter.close();
    }
}
