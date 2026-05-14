package com.seguridad.cookies_demo.controllers;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/sesion")
@CrossOrigin(origins = "http://127.0.0.1:5500", allowCredentials = "true")
public class SesionController {

    // "Base de datos" en memoria para sesiones activas
    private final Map<String, String> sesionesActivas = new HashMap<>();

    // ----------------------------------------------------------------
    // POST /sesion/login
    // Recibe usuario y contraseña, crea una cookie de sesión
    // ----------------------------------------------------------------
    @PostMapping("/login")
    public Map<String, String> login(
            @RequestParam String usuario,
            @RequestParam String password,
            HttpServletResponse response) {

        Map<String, String> resultado = new HashMap<>();

        // Validación simple (en producción usarías BD + contraseña hasheada)
        if ("admin".equals(usuario) && "1234".equals(password)) {

            // 1. Generar un ID de sesión único e impredecible
            String sessionId = UUID.randomUUID().toString();

            // 2. Guardar en "servidor" quién es ese sessionId
            sesionesActivas.put(sessionId, usuario);

            // 3. Crear la cookie
            Cookie cookie = new Cookie("SESSION_ID", sessionId);

            // --- Atributos de seguridad ---
            cookie.setHttpOnly(true);   // No accesible desde JavaScript → protege XSS
            cookie.setSecure(false);    // En producción poner TRUE (solo HTTPS)
            cookie.setPath("/");        // Disponible en toda la app
            cookie.setMaxAge(60 * 30); // Expira en 30 minutos (segundos)

            // 4. Enviar la cookie al navegador en la respuesta HTTP
            response.addCookie(cookie);

            resultado.put("estado", "OK");
            resultado.put("mensaje", "Sesión iniciada para: " + usuario);
            resultado.put("sessionId", sessionId); // Solo para demostración

        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resultado.put("estado", "ERROR");
            resultado.put("mensaje", "Credenciales incorrectas");
        }

        return resultado;
    }

    // ----------------------------------------------------------------
    // GET /sesion/perfil
    // Lee la cookie de sesión y devuelve info del usuario autenticado
    // ----------------------------------------------------------------
    @GetMapping("/perfil")
    public Map<String, String> perfil(HttpServletRequest request,
                                      HttpServletResponse response) {

        Map<String, String> resultado = new HashMap<>();

        // 1. Leer todas las cookies que envió el navegador
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resultado.put("estado", "ERROR");
            resultado.put("mensaje", "No hay cookies. Inicia sesión primero.");
            return resultado;
        }

        // 2. Buscar nuestra cookie específica
        String sessionId = Arrays.stream(cookies)
                .filter(c -> "SESSION_ID".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (sessionId == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resultado.put("estado", "ERROR");
            resultado.put("mensaje", "Cookie SESSION_ID no encontrada.");
            return resultado;
        }

        // 3. Verificar si el sessionId existe en el servidor
        String usuario = sesionesActivas.get(sessionId);

        if (usuario == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resultado.put("estado", "ERROR");
            resultado.put("mensaje", "Sesión inválida o expirada.");
            return resultado;
        }

        // 4. Sesión válida → devolver datos
        resultado.put("estado", "OK");
        resultado.put("usuario", usuario);
        resultado.put("mensaje", "Bienvenido, " + usuario + "! Tu sesión es válida.");

        return resultado;
    }

    // ----------------------------------------------------------------
    // POST /sesion/logout
    // Invalida la cookie de sesión
    // ----------------------------------------------------------------
    @PostMapping("/logout")
    public Map<String, String> logout(HttpServletRequest request,
                                      HttpServletResponse response) {

        Map<String, String> resultado = new HashMap<>();
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("SESSION_ID".equals(cookie.getName())) {

                    // Eliminar del "servidor"
                    sesionesActivas.remove(cookie.getValue());

                    // Invalidar la cookie en el navegador (MaxAge = 0)
                    Cookie cookieVacia = new Cookie("SESSION_ID", "");
                    cookieVacia.setHttpOnly(true);
                    cookieVacia.setPath("/");
                    cookieVacia.setMaxAge(0); // ← esto elimina la cookie del navegador
                    response.addCookie(cookieVacia);

                    resultado.put("estado", "OK");
                    resultado.put("mensaje", "Sesión cerrada correctamente.");
                    return resultado;
                }
            }
        }

        resultado.put("estado", "INFO");
        resultado.put("mensaje", "No había sesión activa.");
        return resultado;
    }

    // ----------------------------------------------------------------
    // GET /sesion/todas-las-cookies
    // Muestra TODAS las cookies (útil para depuración)
    // ----------------------------------------------------------------
    @GetMapping("/todas-las-cookies")
    public Map<String, Object> todasLasCookies(HttpServletRequest request) {

        Map<String, Object> resultado = new HashMap<>();
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            resultado.put("total", 0);
            resultado.put("mensaje", "No se encontraron cookies.");
        } else {
            Map<String, String> mapa = new HashMap<>();
            for (Cookie c : cookies) {
                mapa.put(c.getName(), c.getValue());
            }
            resultado.put("total", cookies.length);
            resultado.put("cookies", mapa);
        }

        return resultado;
    }
}