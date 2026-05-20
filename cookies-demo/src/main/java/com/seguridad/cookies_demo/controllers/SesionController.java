package com.seguridad.cookies_demo.controllers;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.seguridad.cookies_demo.util.JwtUtil;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/sesion")
@CrossOrigin(origins = "*")
public class SesionController {

    @Autowired
    private JwtUtil jwtUtil;

    // Sesiones activas: sessionId -> usuario
    private final Map<String, String> sesionesActivas = new HashMap<>();

    // ── LOGIN: genera cookie de sesión + JWT ─────────────────────────
    @PostMapping("/login")
    public Map<String, Object> login(
            @RequestParam String usuario,
            @RequestParam String password,
            HttpServletResponse response) {

        Map<String, Object> resultado = new HashMap<>();

        if ("admin".equals(usuario) && "1234".equals(password)) {

            // 1. Cookie de sesión (como antes)
            String sessionId = UUID.randomUUID().toString();
            sesionesActivas.put(sessionId, usuario);

            Cookie cookie = new Cookie("SESSION_ID", sessionId);
            cookie.setHttpOnly(true);
            cookie.setSecure(false);
            cookie.setPath("/");
            cookie.setMaxAge(60 * 30);
            response.addCookie(cookie);

            // 2. JWT (nuevo)
            String jwt = jwtUtil.generarToken(usuario);

            resultado.put("estado", "OK");
            resultado.put("mensaje", "Sesión iniciada para: " + usuario);
            resultado.put("sessionId", sessionId);
            resultado.put("token", jwt);

        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resultado.put("estado", "ERROR");
            resultado.put("mensaje", "Credenciales incorrectas");
        }

        return resultado;
    }

    // ── PERFIL: valida cookie Y JWT ──────────────────────────────────
    @GetMapping("/perfil")
    public Map<String, Object> perfil(
            HttpServletRequest request,
            HttpServletResponse response) {

        Map<String, Object> resultado = new HashMap<>();

        // Validar cookie de sesión
        Cookie[] cookies = request.getCookies();
        String sessionId = null;

        if (cookies != null) {
            sessionId = Arrays.stream(cookies)
                    .filter(c -> "SESSION_ID".equals(c.getName()))
                    .map(Cookie::getValue)
                    .findFirst().orElse(null);
        }

        if (sessionId == null || !sesionesActivas.containsKey(sessionId)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resultado.put("estado", "ERROR");
            resultado.put("mensaje", "Cookie de sesión inválida o ausente");
            return resultado;
        }

        // Validar JWT del header Authorization
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resultado.put("estado", "ERROR");
            resultado.put("mensaje", "JWT ausente. Envía: Authorization: Bearer <token>");
            return resultado;
        }

        String jwt = authHeader.substring(7);

        if (!jwtUtil.validarToken(jwt)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resultado.put("estado", "ERROR");
            resultado.put("mensaje", "JWT inválido o expirado");
            return resultado;
        }

        // Ambos válidos
        String usuarioCookie = sesionesActivas.get(sessionId);
        String usuarioJwt    = jwtUtil.extraerUsuario(jwt);

        resultado.put("estado", "OK");
        resultado.put("usuario", usuarioCookie);
        resultado.put("usuarioEnJwt", usuarioJwt);
        resultado.put("mensaje", "Acceso concedido con cookie + JWT ✓");

        return resultado;
    }

    // ── LOGOUT ───────────────────────────────────────────────────────
    @PostMapping("/logout")
    public Map<String, String> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        Map<String, String> resultado = new HashMap<>();
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("SESSION_ID".equals(cookie.getName())) {
                    sesionesActivas.remove(cookie.getValue());

                    Cookie vacia = new Cookie("SESSION_ID", "");
                    vacia.setHttpOnly(true);
                    vacia.setPath("/");
                    vacia.setMaxAge(0);
                    response.addCookie(vacia);

                    resultado.put("estado", "OK");
                    resultado.put("mensaje", "Sesión cerrada. Descarta el JWT en el cliente.");
                    return resultado;
                }
            }
        }

        resultado.put("estado", "INFO");
        resultado.put("mensaje", "No había sesión activa.");
        return resultado;
    }

    // ── VALIDAR JWT (endpoint de prueba) ─────────────────────────────
    @GetMapping("/validar-jwt")
    public Map<String, Object> validarJwt(HttpServletRequest request) {
        Map<String, Object> resultado = new HashMap<>();
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            resultado.put("estado", "ERROR");
            resultado.put("mensaje", "Envía: Authorization: Bearer <token>");
            return resultado;
        }

        String jwt = authHeader.substring(7);

        if (jwtUtil.validarToken(jwt)) {
            resultado.put("estado", "OK");
            resultado.put("usuario", jwtUtil.extraerUsuario(jwt));
            resultado.put("mensaje", "JWT válido ✓");
        } else {
            resultado.put("estado", "ERROR");
            resultado.put("mensaje", "JWT inválido o expirado");
        }

        return resultado;
    }
}