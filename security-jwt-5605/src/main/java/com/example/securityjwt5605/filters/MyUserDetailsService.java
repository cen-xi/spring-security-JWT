package com.example.securityjwt5605.filters;


import com.example.securityjwt5605.model.JwtUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;


/**
 * 这个类其实就是为了获取用户的正确认证信息，不做信息比较，比较是在过滤器里面，
 * 名字叫做 UsernamePasswordAuthenticationFilter
 */

@Service
public class MyUserDetailsService implements UserDetailsService {


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        JwtUser tUser = new JwtUser();
        //权限设置
        List<GrantedAuthority> simpleGrantedAuthorities = new ArrayList<>();
        System.out.println("===============================数据库层对比==================================");


        if (username.equals("cen")) {
            tUser.setUsername(username);
            tUser.setPassword("$2a$10$Qghi7vHdyQJHYlAO.FCo/u3gCbqwWBVaSHjIF0Vci.C5.1l71SExq");
            simpleGrantedAuthorities.add(new SimpleGrantedAuthority("ROLE_user"));
            tUser.setGrantedAuthorities(simpleGrantedAuthorities);
        } else if (username.equals("admin")) {
            tUser.setUsername(username);
            tUser.setPassword("$2a$10$ywq3gn6E15tnY3URptsIz.zn/fznWGqc2VhO4zphS/sIbWZJtLCVK");
            simpleGrantedAuthorities.add(new SimpleGrantedAuthority("ROLE_admin"));
            tUser.setGrantedAuthorities(simpleGrantedAuthorities);
        } else {
            throw new UsernameNotFoundException("没有找到用户");
        }

        //        System.out.println("=============================");
//        //根据用户名去数据库查询用户信息
//        TUser tUser = userService.getByUsername(username);
//        if (tUser == null){
//            throw new UsernameNotFoundException("用户不存在！");
//        }
//        //权限设置
//        List<SimpleGrantedAuthority> simpleGrantedAuthorities = new ArrayList<>();
//        String role = tUser.getRole();
//        //分割权限名称，如 user,admin
//        String[] roles = role.split(",");
//        System.out.println("=============================");
//        System.out.println("注册该账户权限");
//        for (String r :roles){
//            System.out.println(r);
//            //添加权限
//            simpleGrantedAuthorities.add(new SimpleGrantedAuthority("ROLE_"+r));
////            simpleGrantedAuthorities.add(new SimpleGrantedAuthority(r));
//        }
//           tUser.setGrantedAuthorities(simpleGrantedAuthorities);
//        System.out.println("=============================");

        /**
         * 创建一个用于认证的用户对象，包括：用户名，密码，权限
         *
         */
        //输入参数
//        return new org.springframework.security.core.userdetails.User(tUser.getUsername(), tUser.getPassword(), simpleGrantedAuthorities);

//        这个返回值的类型，继承了userdetails即可
        return tUser;

    }


}
