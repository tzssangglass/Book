package kong.training.rest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.HashMap;

@SpringBootApplication
public class KongApplication {

	public static void main(String[] args) {

		HashMap<String, Object> props = new HashMap<>();
		props.put("server.port", 8000);

		new SpringApplicationBuilder()
				.sources(UserController.class,HealthController.class, LBSController.class,ReturnRawController.class,LogController.class)
				.properties(props)
				.run(args);
	}

	/*
	public static void main(String[] args) throws Exception {
		ConfigurableApplicationContext context = SpringApplication.run(UDPReceiveConfig.class, args);
		Thread.sleep(60*1000*10);
		context.close();
	}
	*/

}
