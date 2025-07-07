# Etapa 1: Desarrollo
FROM node:20.12.2-alpine AS development

# Crear directorio de la aplicación
WORKDIR /usr/src/app

# Copiar los archivos de configuración de npm
COPY package*.json ./

# Aumentar el tiempo de espera de NPM
ENV NPM_CONFIG_FETCH_TIMEOUT=120000

# Instalar dependencias de desarrollo
RUN npm ci

# Copiar archivos de configuración y código fuente
COPY tsconfig*.json ./
COPY src/ src/

# Crear la carpeta "dist" con la construcción de producción
RUN npm run build

# Etapa 2: Construcción
FROM node:20.12.2-alpine AS builder

# Crear directorio de la aplicación
WORKDIR /usr/src/app

# Copiar los archivos de configuración de npm
COPY package*.json ./

# Instalar dependencias de producción
RUN npm ci --only=production

# Copiar los archivos necesarios desde la etapa de desarrollo
COPY --from=development /usr/src/app/dist ./dist

# Etapa 3: Producción
FROM node:20.12.2-alpine AS production

# Crear directorio de la aplicación
WORKDIR /usr/src/app

# Copiar solo los archivos necesarios desde la etapa de construcción
COPY --from=builder /usr/src/app/dist ./dist
COPY --from=builder /usr/src/app/package*.json ./

# Aumentar el tiempo de espera de NPM
ENV NPM_CONFIG_FETCH_TIMEOUT=120000

# Instalar solo las dependencias de producción
RUN npm ci --only=production && npm cache clean --force

# Crear un usuario no root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Configurar permisos de archivos y carpetas para el usuario no root
RUN chmod -R 755 /usr/src/app

# Configurar políticas de seguridad adicionales
RUN apk add --no-cache tini

# Cambiar al usuario no root
USER appuser

# Configurar políticas de seguridad adicionales
# Usar Tini como el punto de entrada para manejar señales de sistema
ENTRYPOINT ["/sbin/tini", "--"]

EXPOSE 9999

ENV NODE_ENV=production

# Iniciar el servidor usando la construcción de producción
CMD ["npm", "run", "start:prod"]

