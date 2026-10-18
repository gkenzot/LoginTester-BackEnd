package com.example.loginauthapi;

import com.example.loginauthapi.config.TestDatabaseConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
@Import(TestDatabaseConfig.class)
class LoginAuthApiApplicationTests {

	@Test
	void contextLoads() {
	}

}
