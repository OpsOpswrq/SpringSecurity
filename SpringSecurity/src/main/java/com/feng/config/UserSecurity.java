package com.feng.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
@EnableWebSecurity
public class UserSecurity extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");
        http.formLogin().loginPage("/toLogin").usernameParameter("name").passwordParameter("pwd").loginProcessingUrl("/login");
        //自定义属性的名字和登录界面
        http.csrf().disable();
        //SpringSecurity的防御措施
        http.logout().logoutSuccessUrl("/");
        //退出后的进的界面自定义
        http.rememberMe().rememberMeParameter("remember");
        //设置remember的属性，来记住之前登录的账号
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())//编码
                .withUser("feng").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3").and()
                .withUser("wrq").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
    }
}
