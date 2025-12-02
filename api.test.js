const request = require('supertest');
const app = 'http://localhost:8080';

describe('Pruebas de Integración - API Tasks', () => {

    // PRUEBA 1: Verificar manejo de rutas inexistentes (404)
    test('GET /ruta-inexistente debería devolver 404', async () => {
        const res = await request(app).get('/api/esta-ruta-no-existe');
        expect(res.statusCode).toBe(404);
    });

    // PRUEBA 2: Validar que el Login rechace datos vacíos (400)
    test('POST /login debería fallar si faltan datos (400)', async () => {
        const res = await request(app)
            .post('/login')
            .send({
                username: "usuario_prueba"
                // Falta el password intencionalmente
            });
        
        expect(res.statusCode).toBe(400);
        expect(res.body.message).toBe("Todos los campos son obligatorios");
    });

    // PRUEBA 3: Verificar seguridad en rutas protegidas (401/403)
    test('GET /protected debería denegar acceso sin token', async () => {
        const res = await request(app).get('/protected');
        expect(res.statusCode).toBe(401);
        expect(res.body.message).toBe("Token no proporcionado");
    });
    // PRUEBA 4: LOGIN REAL (La prueba de fuego)
    // Esta prueba va al VPS, busca al usuario "Zero1" en la base de datos real y verifica si entra.
    test('POST /login debería permitir el acceso al usuario Zero1', async () => {
        
        const respuesta = await request(app)
            .post('/login')
            .send({
                username: "Zero1",  
                email: "draco7922@gmail.com",
                password: "Simba123" 
            });
        expect(respuesta.statusCode).toBe(200);
        expect(respuesta.body).toHaveProperty('token'); 
    });

});