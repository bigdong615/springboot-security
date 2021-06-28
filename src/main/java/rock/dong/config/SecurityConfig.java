package rock.dong.config;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1").hasRole("role1")
                .antMatchers("/level2").hasRole("role2")
                .antMatchers("/level3").hasRole("role3");
        http.formLogin();
        http.logout().logoutSuccessUrl("/");
        http.rememberMe(); //使用的是cookie
    }

    //认证
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("rock").password(new BCryptPasswordEncoder().encode("P@55word")).roles("level1", "leve2")
                .and().withUser("root").password("P@55word").roles("level1", "level2", "level3")
                .and().withUser("guest").password("P@55word").roles("level1");
    }
}

