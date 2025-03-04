package auth;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

//23.43 antigo
//27.17
// Preferi implementar como controler : HomeControler
//@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {

        registry.addViewController("/login").setViewName("pages/login");

		registry.addViewController("/").setViewName("pages/home");        
        
        registry.setOrder(Ordered.HIGHEST_PRECEDENCE);
    }
}