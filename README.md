# 🏥 Backend API - Sistema de Videoteca de Enfermería

Backend desarrollado con NestJS para la gestión de contenido educativo de enfermería, incluyendo autenticación con Firebase/Google, manejo de videos y sistema de roles.

## 🚀 Inicio Rápido

### Prerequisites
- **Node.js** (v18 o superior)
- **Docker Desktop** (para PostgreSQL)
- **npm** o **yarn**

### 🔧 Configuración Automática

1. **Verifica la configuración:**
```powershell
.\check-setup.ps1
```

2. **Inicia el proyecto completo:**
```powershell
.\start-dev.ps1
```

### 📝 Configuración Manual

1. **Instalar dependencias:**
```bash
npm install
```

2. **Configurar variables de entorno:**
   - Revisa `.env.dev` y configura las variables necesarias
   - Para desarrollo local, la configuración de DB ya está lista

3. **Iniciar servicios:**
```bash
# Levantar PostgreSQL y PgAdmin
docker-compose up -d

# Ejecutar migraciones (si las hay)
npm run migration:run

# Iniciar aplicación
npm run start:dev
```

## 🌐 URLs del Proyecto

- **API**: http://localhost:9999
- **Swagger Documentation**: http://localhost:9999/api/docs
- **PgAdmin**: http://localhost:5050
  - Email: `root@localhost`
  - Password: `root`

## 🏗️ Arquitectura

### Módulos Principales
- **Auth**: Autenticación con Firebase y Google OAuth
- **Users**: Gestión de usuarios con roles (Estudiante, Profesor, Admin)
- **Videos**: Subida y gestión de videos con AWS S3
- **Categories**: Categorización de contenido
- **Manual**: Gestión de manuales de procedimientos

### Roles de Usuario
- **Estudiante**: Acceso básico a contenido
- **Profesor**: Puede subir y gestionar contenido
- **Administrador**: Control total del sistema

### Seguridad
- JWT con refresh tokens
- Rate limiting
- Helmet para headers de seguridad
- Validación de emails UCN (@alumnos.ucn.cl, @ucn.cl)

## 🔑 Variables de Entorno Importantes

```bash
# Base de datos
POSTGRES_DB=clinic_hub_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=anashei

# JWT
ACCESS_JWT_SECRET=tu-secret-aquí
REFRESH_JWT_SECRET=tu-refresh-secret-aquí

# Firebase (opcional para desarrollo)
FIREBASE_PROJECT_ID=tu-proyecto-id
FIREBASE_PRIVATE_KEY=tu-private-key
FIREBASE_CLIENT_EMAIL=tu-client-email

# AWS S3 (opcional para desarrollo)
AWS_ACCESS_KEY_ID=tu-access-key
AWS_SECRET_ACCESS_KEY=tu-secret-key
AWS_S3_BUCKET_NAME=tu-bucket
```

## 📊 Base de Datos

### Conexión Local
- **Host**: localhost
- **Puerto**: 5432
- **Base de datos**: clinic_hub_db
- **Usuario**: postgres
- **Contraseña**: anashei

### PgAdmin
- **URL**: http://localhost:5050
- **Email**: root@localhost
- **Password**: root

## 🛠️ Scripts Disponibles

```bash
# Desarrollo
npm run start:dev          # Modo desarrollo con hot reload
npm run start:debug        # Modo debug

# Construcción
npm run build              # Compilar para producción
npm run start:prod         # Ejecutar en producción

# Base de datos
npm run migration:generate # Generar nueva migración
npm run migration:run      # Ejecutar migraciones
npm run migration:show     # Mostrar migraciones

# Testing
npm run test               # Tests unitarios
npm run test:e2e          # Tests end-to-end
npm run test:cov          # Coverage

# Calidad de código
npm run lint              # ESLint
npm run format            # Prettier
```

## 🐳 Docker

### Servicios incluidos:
- **PostgreSQL**: Base de datos principal
- **PgAdmin**: Interface web para PostgreSQL
- **API**: Aplicación NestJS (en modo producción)

```bash
# Solo base de datos (desarrollo)
docker-compose up -d clinic_hub_db pgadmin

# Todo el stack (producción)
docker-compose up -d
```

## 🔐 Autenticación

### Métodos soportados:
1. **Firebase Auth**: Token ID de Firebase
2. **Google OAuth**: Login directo con Google

### Endpoints principales:
- `POST /api/v1/auth/firebase` - Login con Firebase
- `POST /api/v1/auth/google` - Login con Google
- `POST /api/v1/auth/refresh` - Renovar tokens

## 📚 Documentación API

La documentación completa de la API está disponible en:
**http://localhost:9999/api/docs** (Swagger)

## 🧪 Testing

```bash
# Tests unitarios
npm run test

# Tests e2e
npm run test:e2e

# Coverage
npm run test:cov
```

## ⚠️ Notas Importantes

1. **Emails UCN**: Solo emails con dominio UCN tienen acceso
2. **Administradores**: Configurados en `src/common/constants/ucn-email.regex.ts`
3. **Subida de archivos**: Timeout extendido para videos grandes
4. **Seguridad**: Headers de seguridad configurados automáticamente

## 🤝 Desarrollo

### Estructura del proyecto:
```
src/
├── auth/           # Autenticación y autorización
├── users/          # Gestión de usuarios
├── videos/         # Manejo de videos
├── categories/     # Categorización
├── manual/         # Manuales de procedimientos
├── config/         # Configuración de la aplicación
├── database/       # Configuración de base de datos
└── common/         # Utilidades compartidas
```

## 📞 Soporte

Para problemas o preguntas:
1. Revisa la documentación en Swagger
2. Verifica los logs de la aplicación
3. Consulta la configuración en `.env.dev`

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

## Deployment

When you're ready to deploy your NestJS application to production, there are some key steps you can take to ensure it runs as efficiently as possible. Check out the [deployment documentation](https://docs.nestjs.com/deployment) for more information.

If you are looking for a cloud-based platform to deploy your NestJS application, check out [Mau](https://mau.nestjs.com), our official platform for deploying NestJS applications on AWS. Mau makes deployment straightforward and fast, requiring just a few simple steps:

```bash
$ npm install -g mau
$ mau deploy
```

With Mau, you can deploy your application in just a few clicks, allowing you to focus on building features rather than managing infrastructure.

## Resources

Check out a few resources that may come in handy when working with NestJS:

- Visit the [NestJS Documentation](https://docs.nestjs.com) to learn more about the framework.
- For questions and support, please visit our [Discord channel](https://discord.gg/G7Qnnhy).
- To dive deeper and get more hands-on experience, check out our official video [courses](https://courses.nestjs.com/).
- Deploy your application to AWS with the help of [NestJS Mau](https://mau.nestjs.com) in just a few clicks.
- Visualize your application graph and interact with the NestJS application in real-time using [NestJS Devtools](https://devtools.nestjs.com).
- Need help with your project (part-time to full-time)? Check out our official [enterprise support](https://enterprise.nestjs.com).
- To stay in the loop and get updates, follow us on [X](https://x.com/nestframework) and [LinkedIn](https://linkedin.com/company/nestjs).
- Looking for a job, or have a job to offer? Check out our official [Jobs board](https://jobs.nestjs.com).

## Support

Nest is an MIT-licensed open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

## Stay in touch

- Author - [Kamil Myśliwiec](https://twitter.com/kammysliwiec)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## License

Nest is [MIT licensed](https://github.com/nestjs/nest/blob/master/LICENSE).
