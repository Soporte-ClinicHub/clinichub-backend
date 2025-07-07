# CHANGELOG

## [Unreleased]

### Added

- Modularización de enums (roles, tipos de interacción, estados de reporte).
- Separación de entidades: VideoInteraction, VideoComment, VideoBookmark, VideoReport.
- CRUD completo para VideoReport y VideoInteraction.
- Uso de DTOs validados con class-validator en todos los endpoints.
- Refactorización de guards (FirebaseAuthGuard, RolesGuard) para centralizar lógica y mejorar seguridad.
- Implementación de patrón de respuesta `{ message, status, data }` en todos los controladores.
- Manejo robusto de errores y logs en servicios y controladores.
- Documentación Swagger en endpoints principales.
- Uso de AuthGuard('jwt') y RolesGuard para proteger rutas sensibles.
- Centralización de la lógica de Firebase en FirebaseService.
- Refactorización de AuthService para separar login y registro, y rotar refresh tokens.
- Creación de archivos de recomendaciones y mejoras de seguridad (AUTH_SECURITY_IMPROVEMENTS.md, MEJORAS_BACKEND.md).

### Changed

- Eliminación de lógica de comentarios y bookmarks de VideoInteraction.
- Modularización de expresiones regulares y constantes.
- Tipado estricto en DTOs y servicios.
- Uso de enums para roles y estados en toda la aplicación.
- Separación de responsabilidades en servicios y controladores.
- Validación de correos institucionales UCN en el guard de Firebase.
- Centralización de la inicialización de firebase-admin.
- Mejoras en la gestión de errores y mensajes de respuesta.

---

**Este changelog resume los cambios estructurales, de seguridad y de buenas prácticas aplicados al backend.**
