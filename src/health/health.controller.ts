import { Controller, Get, HttpStatus } from '@nestjs/common';
import { HealthCheck, HealthCheckService } from '@nestjs/terminus';
import { ApiResponse } from 'src/common/types/ApiResponse.interface';

@Controller('health')
export class HealthController {
  constructor(private health: HealthCheckService) {}

  @Get()
  @HealthCheck()
  async check(): Promise<ApiResponse<any>> {
    try {
      const healthResult = await this.health.check([
        () => ({ api: { status: 'up' } }),
      ]);
      return {
        statusCode: HttpStatus.OK,
        message: 'Health check OK',
        data: healthResult,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error in health check',
        data: null,
      };
    }
  }

  @Get('status')
  getStatus() {
    return {
      status: 'OK',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      port: process.env.APP_PORT || 3000,
      database: process.env.POSTGRES_DB || 'not configured',
      firebase: {
        configured: !!(process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL),
        projectId: process.env.FIREBASE_PROJECT_ID || 'not configured'
      }
    };
  }

  @Get('app-info')
  getAppInfo() {
    return {
      application: {
        name: 'Videoteca de Enfermería',
        version: '1.0.0',
        description: 'Sistema de gestión de contenido educativo para enfermería',
        features: {
          authentication: 'Firebase Google Auth',
          storage: 'AWS S3',
          database: 'PostgreSQL',
          videoStreaming: 'Habilitado',
          manualSystem: 'Sistema completo de manuales'
        }
      },
      modules: {
        manuals: {
          description: 'Explora guías escritas paso a paso sobre temas clínicos con videos incluidos',
          capabilities: ['Creación', 'Lectura', 'Búsqueda', 'Categorización']
        },
        videos: {
          description: 'Aprende con videos que muestran cómo realizar los procedimientos correctamente',
          capabilities: ['Streaming', 'Comentarios', 'Interacciones', 'Reportes', 'Marcadores']
        },
        categories: {
          description: 'Sistema de categorización para organizar contenido',
          capabilities: ['Gestión de categorías', 'Filtrado', 'Organización']
        }
      },
      theme: {
        supportedModes: ['light', 'dark'],
        defaultMode: 'light',
        persistentSettings: true
      }
    };
  }

  @Get('cors-test')
  testCors() {
    return {
      message: 'CORS test successful',
      timestamp: new Date().toISOString(),
      headers: 'Access-Control-Allow-Origin should be present'
    };
  }
}
