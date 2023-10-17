package br.com.alexandreasilva.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.alexandreasilva.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
            
            var servletPath = request.getServletPath();
            
            if(servletPath.equals("/tasks/")){

            
            var auth =  request.getHeader("Authorization").substring("Basic".length()).trim() ; 
            byte [] authCode = Base64.getDecoder().decode(auth);
            var authDecode = new String(authCode);
            String[] credentials = authDecode.split(":");
            String username = credentials[0];
            String password = credentials[1];
            System.out.println(username);
            System.out.println(password);

            var user = this.userRepository.findByUsername(username);
            if(user == null) {
                response.sendError(401, "Usuário não existe");
            } else {
                
                var passVerify =BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if(passVerify.verified) {
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);        
                }else {
                    response.sendError(401, "senha Incorreta.");
                }

            }

        } else {
            filterChain.doFilter(request, response);
        }

    }
}
    
    
