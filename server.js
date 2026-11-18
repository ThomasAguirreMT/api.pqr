
require("dotenv").config();

const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const { body, validationResult } = require("express-validator");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

const db = require("./config/db");
const correoRoutes = require("./routes/correo");
const transporter = require("./config/mail");

// =====================================================
// FUNCIONES DE SEGURIDAD
// =====================================================

const normalizarCorreo = (correo) =>
    String(correo || "").trim().toLowerCase();

const hash = (value) =>
    crypto.createHash("sha256").update(value).digest("hex");

const compararHashes = (a, b) => {
    if (
        typeof a !== "string" ||
        typeof b !== "string" ||
        !/^[a-f0-9]{64}$/i.test(a) ||
        !/^[a-f0-9]{64}$/i.test(b)
    ) {
        return false;
    }

    const hashA = Buffer.from(a, "hex");
    const hashB = Buffer.from(b, "hex");

    return (
        hashA.length === hashB.length &&
        crypto.timingSafeEqual(hashA, hashB)
    );
};

const escaparHTML = (valor) =>
    String(valor ?? "").replace(/[&<>"']/g, (caracter) => {
        const entidades = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        };

        return entidades[caracter];
    });

const eliminarArchivo = async (archivo) => {
    if (!archivo) return;

    try {
        await fs.promises.unlink(archivo);
    } catch (error) {
        if (error.code !== "ENOENT") {
            console.error("No se pudo eliminar el archivo:", error.message);
        }
    }
};

// =====================================================
// CONFIGURACIÓN DE MULTER
// =====================================================

const uploadPath = path.join(__dirname, "uploads", "pqr");

if (!fs.existsSync(uploadPath)) {
    fs.mkdirSync(uploadPath, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadPath);
    },

    filename: (req, file, cb) => {
        const extension = path.extname(file.originalname).toLowerCase();

        const nombre =
            Date.now() +
            "-" +
            crypto.randomBytes(8).toString("hex") +
            extension;

        cb(null, nombre);
    }
});

const upload = multer({
    storage,

    limits: {
        fileSize: 10 * 1024 * 1024
    },

    fileFilter(req, file, cb) {
        const permitidos = [
            "application/pdf",
            "image/jpeg",
            "image/jpg",
            "image/png"
        ];

        if (permitidos.includes(file.mimetype)) {
            return cb(null, true);
        }

        cb(new Error("Formato de archivo no permitido."));
    }
});

// =====================================================
// MIDDLEWARES
// =====================================================

app.use(helmet());

const allowedOrigins = [
    "http://localhost:3000",
    "http://localhost:5173",

    "https://internetdedicado.com",
    "https://www.internetdedicado.com",

    "https://webmastercolombia.net",
    "https://www.webmastercolombia.net"
];

app.use(cors({
    origin(origin, callback) {
        if (!origin) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        callback(new Error("Origen no permitido por CORS."));
    }
}));

app.use(express.json({
    limit: "100kb"
}));

app.use(morgan("combined"));

app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: "draft-8",
    legacyHeaders: false,

    message: {
        success: false,
        message: "Demasiadas solicitudes. Intenta nuevamente más tarde."
    }
}));

// =====================================================
// RUTAS DE VERIFICACIÓN DE CORREO
// =====================================================

app.use("/correo", correoRoutes);

// =====================================================
// RUTA PRINCIPAL
// =====================================================

app.get("/", (req, res) => {
    res.send("Backend PQR funcionando.");
});

// =====================================================
// CATÁLOGOS
// =====================================================

app.get("/tipos-identificacion", async (req, res) => {
    try {
        const [rows] = await db.execute(
            "SELECT * FROM tipo_identificacion"
        );

        res.json(rows);

    } catch (error) {
        console.error("ERROR TIPOS IDENTIFICACIÓN:", error);

        res.status(500).json({
            success: false,
            message: "No fue posible consultar los tipos de identificación."
        });
    }
});

app.get("/tipos-pqr", async (req, res) => {
    try {
        const [rows] = await db.execute(
            "SELECT * FROM tipo_pqr"
        );

        res.json(rows);

    } catch (error) {
        console.error("ERROR TIPOS PQR:", error);

        res.status(500).json({
            success: false,
            message: "No fue posible consultar los tipos de PQR."
        });
    }
});

app.get("/solicitudes/:id", async (req, res) => {
    try {
        const [rows] = await db.execute(
            "SELECT * FROM solicitud WHERE tipo_pqr_id = ?",
            [req.params.id]
        );

        res.json(rows);

    } catch (error) {
        console.error("ERROR SOLICITUDES:", error);

        res.status(500).json({
            success: false,
            message: "No fue posible consultar las solicitudes."
        });
    }
});

app.get("/motivos/:id", async (req, res) => {
    try {
        const [rows] = await db.execute(
            "SELECT * FROM motivo WHERE solicitud_id = ?",
            [req.params.id]
        );

        res.json(rows);

    } catch (error) {
        console.error("ERROR MOTIVOS:", error);

        res.status(500).json({
            success: false,
            message: "No fue posible consultar los motivos."
        });
    }
});

// =====================================================
// VALIDACIONES DEL FORMULARIO
// =====================================================

const validatePQR = [
    body("nombre")
        .trim()
        .notEmpty()
        .withMessage("El nombre es obligatorio.")
        .isLength({ max: 150 })
        .withMessage("El nombre supera el máximo permitido."),

    body("correo")
        .trim()
        .isEmail()
        .withMessage("Correo inválido.")
        .isLength({ max: 150 })
        .withMessage("El correo supera el máximo permitido."),

    body("descripcion")
        .trim()
        .notEmpty()
        .withMessage("La descripción es obligatoria.")
];

// =====================================================
// CREAR PQR CON VERIFICACIÓN OBLIGATORIA
// =====================================================

app.post(
    "/pqr",
    upload.single("archivo"),
    validatePQR,
    async (req, res) => {

        let connection;
        let transaccionIniciada = false;
        let bloqueoAdquirido = false;
        let registroConfirmado = false;

        const archivoFisico = req.file ? req.file.path : null;

        try {
            // ---------------------------------------------
            // VALIDAR FORMULARIO
            // ---------------------------------------------

            const errors = validationResult(req);

            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: "Revisa los datos del formulario.",
                    errors: errors.array()
                });
            }

            const data = req.body;

            data.correo = normalizarCorreo(data.correo);

            // ---------------------------------------------
            // VALIDAR TOKEN
            // ---------------------------------------------

            const token = String(data.token || "").trim();

            if (!/^[a-f0-9]{64}$/i.test(token)) {
                return res.status(401).json({
                    success: false,
                    message: "Debes verificar tu correo antes de registrar la PQR."
                });
            }

            const tokenHash = hash(token);

            connection = await db.getConnection();

            await connection.beginTransaction();
            transaccionIniciada = true;

            // Buscar el último registro de verificación válido.
            // FOR UPDATE bloquea el registro durante la transacción.

            const [verificaciones] = await connection.execute(
                `
                SELECT
                    id,
                    correo,
                    token_hash,
                    token_expiracion,
                    token_usado
                FROM verificacion_correo
                WHERE correo = ?
                  AND verificado = 1
                  AND usado = 1
                ORDER BY id DESC
                LIMIT 1
                FOR UPDATE
                `,
                [data.correo]
            );

            if (verificaciones.length === 0) {
                await connection.rollback();
                transaccionIniciada = false;

                return res.status(401).json({
                    success: false,
                    message: "No existe una verificación válida para este correo."
                });
            }

            const verificacion = verificaciones[0];

            // Comprobar que el token no haya sido utilizado.

            if (Number(verificacion.token_usado) === 1) {
                await connection.rollback();
                transaccionIniciada = false;

                return res.status(401).json({
                    success: false,
                    message: "Este código de verificación ya fue utilizado. Verifica nuevamente tu correo."
                });
            }

            // Comprobar la vigencia del token.

            const expiracion = new Date(verificacion.token_expiracion);

            if (
                !verificacion.token_expiracion ||
                Number.isNaN(expiracion.getTime()) ||
                Date.now() > expiracion.getTime()
            ) {
                await connection.rollback();
                transaccionIniciada = false;

                return res.status(401).json({
                    success: false,
                    message: "La verificación ha expirado. Solicita un nuevo código."
                });
            }

            // Comparar el hash del token recibido con el almacenado.

            if (!compararHashes(verificacion.token_hash, tokenHash)) {
                await connection.rollback();
                transaccionIniciada = false;

                return res.status(401).json({
                    success: false,
                    message: "El token de verificación no es válido."
                });
            }

            // ---------------------------------------------
            // PROTEGER GENERACIÓN DEL RADICADO
            // ---------------------------------------------

            const year = new Date().getFullYear();
            const yearCUN = String(year).slice(-2);

            const CUN = "7802";

            // Bloqueo nombrado para evitar consecutivos duplicados
            // cuando llegan varias solicitudes simultáneamente.

            const nombreBloqueo = `pqr_consecutivo_${year}`;

            const [bloqueos] = await connection.query(
                "SELECT GET_LOCK(?, 10) AS adquirido",
                [nombreBloqueo]
            );

            if (Number(bloqueos[0].adquirido) !== 1) {
                throw new Error("No fue posible obtener el bloqueo del consecutivo.");
            }

            bloqueoAdquirido = true;

            const [rows] = await connection.execute(
                `
                SELECT MAX(consecutivo) AS consecutivo
                FROM pqr
                WHERE YEAR(fecha) = ?
                `,
                [year]
            );

            const consecutivo =
                Number(rows[0].consecutivo || 0) + 1;

            const radicado =
                `${CUN}-${yearCUN}-${String(consecutivo).padStart(8, "0")}`;

            // ---------------------------------------------
            // INSERTAR PQR
            // ---------------------------------------------

            const archivo = req.file
                ? `uploads/pqr/${req.file.filename}`
                : null;

            await connection.execute(
                `
                INSERT INTO pqr
                (
                    radicado,
                    consecutivo,
                    tipo_identificacion_id,
                    numero_identificacion,
                    tipo_pqr_id,
                    solicitud_id,
                    motivo_id,
                    observaciones,
                    archivo,
                    nombre,
                    documento,
                    correo,
                    telefono,
                    asunto,
                    descripcion
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [
                    radicado,
                    consecutivo,
                    data.tipo_identificacion || null,
                    data.documento || null,
                    data.tipo || null,
                    data.area || null,
                    data.motivo || null,
                    "",
                    archivo,
                    data.nombre,
                    data.documento || null,
                    data.correo,
                    data.telefono || null,
                    data.asunto || null,
                    data.descripcion
                ]
            );

            // ---------------------------------------------
            // OBTENER NOMBRES DE LOS CATÁLOGOS
            // ---------------------------------------------

            const [info] = await connection.execute(
                `
                SELECT
                    (SELECT nombre
                     FROM tipo_pqr
                     WHERE id = ?) AS tipo_nombre,

                    (SELECT nombre
                     FROM solicitud
                     WHERE id = ?) AS solicitud_nombre,

                    (SELECT nombre
                     FROM motivo
                     WHERE id = ?) AS motivo_nombre
                `,
                [
                    data.tipo || null,
                    data.area || null,
                    data.motivo || null
                ]
            );

            const nombres = info[0];

            // ---------------------------------------------
            // CONSUMIR TOKEN
            // ---------------------------------------------

            const [actualizacion] = await connection.execute(
                `
                UPDATE verificacion_correo
                SET token_usado = 1
                WHERE id = ?
                  AND token_usado = 0
                `,
                [verificacion.id]
            );

            if (actualizacion.affectedRows !== 1) {
                throw new Error("No fue posible consumir el token de verificación.");
            }

            // ---------------------------------------------
            // CONFIRMAR TRANSACCIÓN
            // ---------------------------------------------

            await connection.commit();
            transaccionIniciada = false;
            registroConfirmado = true;

            // Liberar el bloqueo del consecutivo.
            // La PQR ya quedó registrada.

            if (bloqueoAdquirido) {
                await connection.query(
                    "SELECT RELEASE_LOCK(?)",
                    [nombreBloqueo]
                );

                bloqueoAdquirido = false;
            }

            connection.release();
            connection = null;

            // ---------------------------------------------
            // PREPARAR DATOS SEGUROS PARA LOS CORREOS
            // ---------------------------------------------

            const nombreSeguro = escaparHTML(data.nombre);
            const documentoSeguro = escaparHTML(data.documento);
            const correoSeguro = escaparHTML(data.correo);
            const telefonoSeguro = escaparHTML(data.telefono);
            const asuntoSeguro = escaparHTML(data.asunto);
            const descripcionSegura = escaparHTML(data.descripcion)
                .replace(/\r?\n/g, "<br>");

            const tipoSeguro = escaparHTML(nombres.tipo_nombre);
            const solicitudSegura = escaparHTML(nombres.solicitud_nombre);
            const motivoSeguro = escaparHTML(nombres.motivo_nombre);

            const archivoSeguro = archivo
                ? escaparHTML(archivo)
                : null;

            // ---------------------------------------------
            // CORREO INTERNO
            // ---------------------------------------------

            try {
                await transporter.sendMail({
                    from: `Sistema PQR <${process.env.EMAIL_USER}>`,
                    to: process.env.EMAIL_USER,
                    subject: `Nueva PQR ${radicado}`,

                    html: `
                        <h2>Nueva PQR recibida</h2>
                        <hr>

                        <p><b>Radicado:</b> ${radicado}</p>
                        <p><b>Nombre:</b> ${nombreSeguro}</p>
                        <p><b>Documento:</b> ${documentoSeguro}</p>
                        <p><b>Correo:</b> ${correoSeguro}</p>
                        <p><b>Teléfono:</b> ${telefonoSeguro}</p>
                        <p><b>Tipo:</b> ${tipoSeguro}</p>
                        <p><b>Solicitud:</b> ${solicitudSegura}</p>
                        <p><b>Motivo:</b> ${motivoSeguro}</p>
                        <p><b>Asunto:</b> ${asuntoSeguro}</p>

                        <p><b>Descripción:</b></p>
                        <p>${descripcionSegura}</p>

                        ${
                            archivoSeguro
                                ? `<p><b>Archivo adjunto:</b> ${archivoSeguro}</p>`
                                : "<p><b>Sin archivo adjunto.</b></p>"
                        }
                    `
                });

            } catch (err) {
                console.error("Error enviando correo interno:", err.message);
            }

            // ---------------------------------------------
            // CORREO AL CLIENTE
            // ---------------------------------------------

            try {
                await transporter.sendMail({
                    from: `Sistema PQR <${process.env.EMAIL_USER}>`,
                    to: data.correo,
                    subject: `Confirmación de radicado ${radicado}`,

                    html: `
                        <h2>Hemos recibido tu solicitud</h2>

                        <p>Hola <b>${nombreSeguro}</b>,</p>

                        <p>Tu solicitud fue registrada correctamente.</p>

                        <p>Tu número de radicado es:</p>

                        <h2>${radicado}</h2>

                        <p>Conserva este número para futuras consultas.</p>

                        <hr>

                        <p>Webmaster Colombia</p>
                    `
                });

            } catch (err) {
                console.error("Error enviando correo al cliente:", err.message);
            }

            // ---------------------------------------------
            // RESPUESTA
            // ---------------------------------------------

            return res.status(200).json({
                success: true,
                message: "PQR registrada correctamente.",
                radicado
            });

        } catch (error) {
            console.error("ERROR GENERAL PQR:", error);

            if (connection && transaccionIniciada) {
                await connection.rollback().catch(() => {});
                transaccionIniciada = false;
            }

            return res.status(500).json({
                success: false,
                message: "No fue posible registrar la PQR. Intenta nuevamente."
            });

        } finally {
            // Liberar bloqueo si hubo algún error.

            if (connection && bloqueoAdquirido) {
                try {
                    await connection.query(
                        "SELECT RELEASE_LOCK(?)",
                        [`pqr_consecutivo_${new Date().getFullYear()}`]
                    );
                } catch (error) {
                    console.error("Error liberando bloqueo:", error.message);
                }
            }

            // Liberar conexión si todavía está abierta.

            if (connection) {
                connection.release();
            }

            // Si no se confirmó la PQR, eliminar el archivo recibido.

            if (!registroConfirmado && archivoFisico) {
                await eliminarArchivo(archivoFisico);
            }
        }
    }
);

// =====================================================
// ERRORES DE MULTER Y OTROS MIDDLEWARES
// =====================================================

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        return res.status(400).json({
            success: false,
            message: err.code === "LIMIT_FILE_SIZE"
                ? "El archivo supera el tamaño máximo permitido de 10 MB."
                : "No fue posible procesar el archivo adjunto."
        });
    }

    if (err) {
        console.error("ERROR MIDDLEWARE:", err.message);

        return res.status(
            err.message === "Origen no permitido por CORS." ? 403 : 400
        ).json({
            success: false,
            message: err.message === "Origen no permitido por CORS."
                ? "Origen no permitido."
                : err.message
        });
    }

    next();
});

// =====================================================
// INICIAR SERVIDOR
// =====================================================

const PORT = process.env.PORT || 4000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Servidor ejecutándose en el puerto ${PORT}`);
});
