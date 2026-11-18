
const express = require("express");
const crypto = require("crypto");

const router = express.Router();

const db = require("../config/db");
const transporter = require("../config/mail");

const hash = (value) =>
    crypto.createHash("sha256").update(value).digest("hex");

const normalizarCorreo = (correo) =>
    String(correo || "").trim().toLowerCase();
const correoValido = (correo) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo);

const compararHashes = (a, b) => {
    const hashA = Buffer.from(a, "hex");
    const hashB = Buffer.from(b, "hex");

    return hashA.length === hashB.length &&
        crypto.timingSafeEqual(hashA, hashB);
};

/*=====================================================
  ENVIAR CÓDIGO DE VERIFICACIÓN
=====================================================*/

router.post("/enviar-codigo", async (req, res) => {
    let connection;
    let registroId;

    try {
        const correo = normalizarCorreo(req.body.correo);

        if (!correo || !correoValido(correo) || correo.length > 150) {
            return res.status(400).json({
                success: false,
                message: "Debes ingresar un correo válido."
            });
        }

        connection = await db.getConnection();

        // Control de reenvío: esperar 60 segundos.
        const [anteriores] = await connection.execute(
            `SELECT id, fecha_creacion
             FROM verificacion_correo
             WHERE correo = ?
             ORDER BY id DESC
             LIMIT 1`,
            [correo]
        );

        if (anteriores.length > 0) {
            const ultimaFecha = new Date(anteriores[0].fecha_creacion);
            const segundos = (Date.now() - ultimaFecha.getTime()) / 1000;

            if (segundos < 60) {
                return res.status(429).json({
                    success: false,
                    message: "Espera un minuto antes de solicitar otro código."
                });
            }
        }

        const codigo = crypto.randomInt(100000, 1000000).toString();
        const codigoHash = hash(codigo);

        const fechaExpiracion = new Date(Date.now() + 10 * 60 * 1000);

        await connection.execute(
            `UPDATE verificacion_correo
     SET token_usado = 1
     WHERE correo = ?
     AND token_usado = 0`,
            [correo]
        );

        const [resultado] = await connection.execute(

            `INSERT INTO verificacion_correo
             (
                correo,
                codigo,
                intentos,
                verificado,
                usado,
                token_hash,
                token_expiracion,
                token_usado,
                fecha_expiracion
             )
             VALUES (?, ?, 0, 0, 0, NULL, NULL, 0, ?)`,
            [correo, codigoHash, fechaExpiracion]
        );

        registroId = resultado.insertId;

        await transporter.sendMail({
            from: `Sistema PQR <${process.env.EMAIL_USER}>`,
            to: correo,
            subject: "Código de verificación - Sistema PQR",
            html: `
                <h2>Verificación de correo</h2>
                <p>Tu código de verificación es:</p>
                <h1 style="letter-spacing: 5px">${codigo}</h1>
                <p>Este código es válido durante 10 minutos.</p>
                <p>Si no solicitaste este código, puedes ignorar este mensaje.</p>
            `
        });

        return res.json({
            success: true,
            message: "Código enviado correctamente."
        });

    } catch (error) {
        console.error("ERROR ENVIAR CÓDIGO:", error);

        // Si falla el envío, invalidar el código recién creado.
        if (connection && registroId) {
            await connection.execute(
                `UPDATE verificacion_correo
                 SET usado = 1
                 WHERE id = ?`,
                [registroId]
            ).catch(() => { });
        }

        return res.status(500).json({
            success: false,
            message: "No fue posible enviar el código."
        });

    } finally {
        if (connection) connection.release();
    }
});


/*=====================================================
  VERIFICAR CÓDIGO Y GENERAR TOKEN
=====================================================*/

router.post("/verificar", async (req, res) => {
    let connection;

    try {
        const correo = normalizarCorreo(req.body.correo);
        const codigo = String(req.body.codigo || "").trim();

        if (!correoValido(correo) || !/^\d{6}$/.test(codigo)) {
            return res.status(400).json({
                success: false,
                message: "Correo o código inválido."
            });
        }

        connection = await db.getConnection();
        await connection.beginTransaction();

        const [rows] = await connection.execute(
            `SELECT *
             FROM verificacion_correo
             WHERE correo = ?
             AND usado = 0
             ORDER BY id DESC
             LIMIT 1
             FOR UPDATE`,
            [correo]
        );

        if (rows.length === 0) {
            await connection.rollback();

            return res.status(400).json({
                success: false,
                message: "No existe un código pendiente de verificación."
            });
        }

        const registro = rows[0];

        if (registro.intentos >= 5) {
            await connection.rollback();

            return res.status(429).json({
                success: false,
                message: "Superaste el máximo de intentos. Solicita un nuevo código."
            });
        }

        if (Date.now() > new Date(registro.fecha_expiracion).getTime()) {
            await connection.execute(
                `UPDATE verificacion_correo
                 SET usado = 1
                 WHERE id = ?`,
                [registro.id]
            );

            await connection.commit();

            return res.status(400).json({
                success: false,
                message: "El código ha expirado. Solicita uno nuevo."
            });
        }

        const codigoHash = hash(codigo);

        if (!compararHashes(registro.codigo, codigoHash)) {
            await connection.execute(
                `UPDATE verificacion_correo
                 SET intentos = intentos + 1
                 WHERE id = ?`,
                [registro.id]
            );

            await connection.commit();

            return res.status(400).json({
                success: false,
                message: "Código incorrecto."
            });
        }

        // Token aleatorio de 256 bits.
        const token = crypto.randomBytes(32).toString("hex");
        const tokenHash = hash(token);

        // Vigencia de 30 minutos.
        const tokenExpiracion = new Date(Date.now() + 30 * 60 * 1000);

        await connection.execute(
            `UPDATE verificacion_correo
             SET
                verificado = 1,
                usado = 1,
                token_hash = ?,
                token_expiracion = ?,
                token_usado = 0
             WHERE id = ?`,
            [tokenHash, tokenExpiracion, registro.id]
        );

        await connection.commit();

        return res.json({
            success: true,
            message: "Correo verificado correctamente.",
            token,
            expiresIn: 1800
        });

    } catch (error) {
        if (connection) {
            await connection.rollback().catch(() => { });
        }

        console.error("ERROR VERIFICAR CÓDIGO:", error);

        return res.status(500).json({
            success: false,
            message: "No fue posible verificar el código."
        });

    } finally {
        if (connection) connection.release();
    }
});

module.exports = router;
