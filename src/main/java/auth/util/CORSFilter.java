package auth.util;

import java.io.IOException;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//Solução encontrada na internet. funciona também, mas
//NAO GOSTEI - nao eh assim.


//@Component
//@Order(Ordered.HIGHEST_PRECEDENCE)
public class CORSFilter implements Filter {

//    private final Set<String> allowedOrigins;

    @Autowired
    public CORSFilter(@Value("${spring.security.cors.allowed-origins:*}") Set<String> allowedOrigins) {
//        this.allowedOrigins = allowedOrigins;
    }

    @Override
    public void init(FilterConfig fc) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) 
    throws IOException, ServletException {
    	
        HttpServletResponse response = (HttpServletResponse) resp;
        HttpServletRequest request = (HttpServletRequest) req;

//SE VERIFICA PELO 'Origin' , NAO PELO REFERER        
//        String origin = request.getHeader("referer");
//        if(origin != null ){
//            Optional<String> first = allowedOrigins.stream().filter(origin::startsWith).findFirst();
//            first.ifPresent(s -> response.setHeader("Access-Control-Allow-Origin", s));
//        }
        
        //DEVEM SER INSERIDOS APENAS NAS REQUISICOES 'OPTIONS'
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE");
        response.setHeader("Access-Control-Max-Age", "3600");
        response.setHeader("Access-Control-Allow-Headers", "*"); //"x-requested-with, authorization, Content-Type, Authorization, credential, X-XSRF-TOKEN");

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            chain.doFilter(req, resp);
        }
    }

    @Override
    public void destroy() {
    }

}