package Authentication.Project1.Authify.Controller;

import Authentication.Project1.Authify.Service.AppUserDetailsService;
import Authentication.Project1.Authify.Util.JwtUtil;
import Authentication.Project1.Authify.io.AuthRequest;
import Authentication.Project1.Authify.io.AuthResponse;
import io.jsonwebtoken.Jwt;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager manager;
    private final AppUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest){
        try{
            authenticate(authRequest.getEmail() , authRequest.getPassword());
            final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getEmail());
            final String JwtToken = jwtUtil.generateToken(userDetails);
            ResponseCookie cookie = ResponseCookie.from("jwt" , JwtToken)
                    .httpOnly(true)
                    .path("/")
                    .maxAge(Duration.ofDays(1))
                    .sameSite("Strict")
                    .build();

            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE , cookie.toString())
                    .body(new AuthResponse(authRequest.getEmail(), JwtToken));
        } catch (BadCredentialsException e) {
            Map<String , Object> map = new HashMap<>();
            map.put("error" , true);
            map.put("message" , "Email or Password is Incorrect");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(map);
        }catch (DisabledException ex){
            Map<String , Object> map = new HashMap<>();
            map.put("error" , true);
            map.put("message" , "Account is Disabled");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(map);
        }catch(Exception exception){
            Map<String , Object> map = new HashMap<>();
            map.put("error" , true);
            map.put("message" , "Authentication is Failed");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(map);
        }
    }

    private void authenticate(String email, String password) {
        manager.authenticate(new UsernamePasswordAuthenticationToken(email,password));
    }


}
