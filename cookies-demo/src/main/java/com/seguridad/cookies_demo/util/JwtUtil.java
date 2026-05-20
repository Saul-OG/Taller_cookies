package com.seguridad.cookies_demo.util;

import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
 
    // Clave secreta para firmar el token (mínimo 256 bits para HS256)
    private final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
 
    // Tiempo de expiración: 30 minutos (igual que la cookie)
    private final long EXPIRATION_MS = 1000 * 60 * 30;
 
    // Genera un JWT para el usuario dado
    public String generarToken(String usuario) {
        return Jwts.builder()
                .setSubject(usuario)                         // quién es el usuario
                .setIssuedAt(new Date())                     // cuándo se creó
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_MS)) // cuándo expira
                .signWith(SECRET_KEY)                        // firmado con nuestra clave
                .compact();
    }
 
    // Extrae el nombre de usuario del token
    public String extraerUsuario(String token) {
        return getClaims(token).getSubject();
    }
 
    // Valida que el token sea correcto y no haya expirado
    public boolean validarToken(String token) {
        try {
            Claims claims = getClaims(token);
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return false; // token inválido, manipulado o expirado
        }
    }
 
    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
 