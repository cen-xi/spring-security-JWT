package com.example.securityjwt5605.filters;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.GenericFilterBean;
import sun.plugin.liveconnect.SecurityContextHelper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.Security;
import java.util.List;

/**
 * 对携带token的请求做token检查，对比是否正确，正确则可以直接通过
 */

public class JwtFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("===============================token登录拦截1==================================");

        //强转http请求
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        //从请求头获取数据
        //定死了名称为 authorization
        String tokenStr = httpServletRequest.getHeader("authorization");
        System.out.println(tokenStr);
        /*
        打印结果 【不可换行，这里为了展示才换行】
        Bearer eyJhbGciOiJIUzUxMiJ9.eyJhdXRob3JpdGllcyI6IlJPTEVfYWRtaW4sIiwic3ViIjoiYWRtaW4iLCJleHAi
        OjE1OTE2MzAwMTF9.oHmTl-f5RetmFJ8rM5MaIruOkA83sqt-6F7f2c27QRWdJvTAOIYX_VbRCngodaROZ4jprQ1ktwz5sZAWcDJdkg

         */

        System.out.println("==========================================");
        if (tokenStr != null) {
            System.out.println("有认证令牌");
            boolean k = true;
            Jws<Claims> jws = null;
            try {
                //解析,解析方式使用加密时配置的数字签名对应
                //一旦令牌修改成位数对比不上，会报错。。。
                jws = Jwts.parser().setSigningKey("java521@java")
                        .parseClaimsJws(tokenStr.replace("Bearer", ""));
                System.out.println(tokenStr.replace("Bearer", ""));
                  /*
                  打印结果 【不可换行，这里为了展示才换行】
                     eyJhbGciOiJIUzUxMiJ9.eyJhdXRob3JpdGllcyI6IlJPTEVfYWRtaW4sIiwic3ViIjoiYWRtaW4iLCJleHAiOjE
                     1OTE2MzAwMTF9.oHmTl-f5RetmFJ8rM5MaIruOkA83sqt-6F7f2c27QRWdJvTAOIYX_VbRCngodaROZ4jprQ1ktwz5sZAWcDJdkg
                  */
            } catch (Exception e) {
                //放令牌被修改、时间过期，都会抛出异常,由方法 parseClaimsJws（）安抛出的异常
//                e.printStackTrace();
                k = false;
            }
            if (k) {
                // 令牌解析成功
                Claims claims = jws.getBody();
                //获取token解析出来的用户名
                String username = claims.getSubject();
                System.out.println(username);
                 /*
                  打印结果
                   [ROLE_admin,ROLE_user,等等]
                  */
                //从token获取登录角色的权限
                //如果时以逗号格式配置字符串，可用以下方式解析,否则手动解析
                List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get("authorities"));
                System.out.println(grantedAuthorities);
                //

                //new令牌登录校验 对象，参数分别是  ： 用户名 ，盐[没有则设为null] ，角色/权限
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);
                //执行令牌登录校验
                SecurityContextHolder.getContext().setAuthentication(token);
            } else {
                System.out.println("令牌解析失败，被修改了");
                SecurityContextHolder.getContext()
                        .setAuthentication(new UsernamePasswordAuthenticationToken(null, null, null));
            }
        } else {
            System.out.println("没有认证令牌");
            SecurityContextHolder.getContext()
                    .setAuthentication(new UsernamePasswordAuthenticationToken(null, null, null));
        }
        System.out.println("//让过滤器继续往下走，");
        //让过滤器继续往下走
        filterChain.doFilter(servletRequest, servletResponse);

    }
}


/*
总结：
1.生成token 的变化数据是用户名和权限拼接的字符串 ，其他的固定
2.生成的token是将登录通过的用户的权限拼接的字符串加密后放入里面后加密，当携带token访问时被拦截后，会将token解析出的权限注册，因为不与数据库等数据共享校验权限最新信息，
如果在携带token的请求前权限有变化，但是token却没有改变，会导致token权限与用户真实权限不一致，形成脏数据啦！！！
如果权限增加还好，使得无法访问新加权限的操作，如果是减少权限，比如vip过期，用户仍然可以有vip权限。
3.解决token脏数据的方案有两个：
（1）等待该token失效时间【不靠谱】；
（2）每次修改权限时，会强制使得token失效，具体怎么做，还没试过
4.当然，也有优点的，不与数据库等最新数据做权限对比操作，较少了访问数据库该用户信息的部分，能快速的过滤请求权限，理论上访问数据会变快。
5.可以设置过期时间，单位毫秒，用时间戳设置 ，到时间则不可在使用，
但是缺点很明显，在未过期之前，可以无数次访问验证通过，无法控制使用次数，
因此不能作为资源服务器对第三方应用开放的授权令牌，
6.令牌格式对不上，会直接报错异常，为了服务降级，做个异常捕获即可
7.如果生成了新的令牌，旧的令牌仍然可以使用，因此会导致多设备同时登录的情况，无法控制登录数量
8.使用jwt[java web token],做登录校验，则会导致http.sessionManagement().maximumSessions(1);设置失效，因为没有使用session做为登录控制
//
安全弊端很多 ， 但是让我深刻明白了token的内部思想
 */