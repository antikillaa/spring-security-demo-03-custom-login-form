package by.peshkur.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // add our users in memory

        User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();

        auth.inMemoryAuthentication()
                .withUser(userBuilder.username("stas").password("test123").roles("EMPLOYEE"));
        auth.inMemoryAuthentication()
                .withUser(userBuilder.username("toma").password("test123").roles("MANAGER"));
        auth.inMemoryAuthentication()
                .withUser(userBuilder.username("mary").password("test123").roles("ADMIN"));
    }

}
