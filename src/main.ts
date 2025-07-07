import compression from 'compression';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

import {
  ClassSerializerInterceptor,
  Logger,
  ValidationPipe,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { NestFactory, Reflector } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

import { AppModule } from './app.module';
import { TimeoutInterceptor } from './common/interceptors/time-out.interceptor';
import config from './config/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bodyParser: true });

  const logger = new Logger('Main');

  const configService = app.get<ConfigType<typeof config>>(config.KEY);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
      disableErrorMessages: false,
    }),
  );

  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));

  app.useGlobalInterceptors(new TimeoutInterceptor(300000));

  app.setGlobalPrefix('api/v1');

  // Configure CORS with more specific settings
  app.enableCors({
    origin: [
      'https://videoteca-web-enfermeria.vercel.app', // Production frontend
      'http://localhost:3000', // React dev server
      'http://localhost:3001', // Alternative React port
      'http://localhost:5173', // Vite dev server (primary)
      'http://localhost:5174', // Vite dev server (alternative)
      'http://localhost:8080', // Alternative frontend port
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type', 
      'Authorization', 
      'Accept', 
      'X-Requested-With',
      'Origin',
      'Cache-Control',
      'Content-Length'
    ],
    exposedHeaders: ['set-cookie'],
    optionsSuccessStatus: 200, // Some legacy browsers choke on 204
    preflightContinue: false,
  });

  // Add specific CORS handling for video uploads
  app.use('/api/v1/videos/upload', (req, res, next) => {
    if (req.method === 'OPTIONS') {
      res.header('Access-Control-Allow-Origin', 'https://videoteca-web-enfermeria.vercel.app');
      res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, X-Requested-With, Origin');
      res.header('Access-Control-Max-Age', '86400');
      return res.status(200).end();
    }
    next();
  });

  app.use(helmet({}));

  app.use(compression());

  // Request logging middleware
  app.use((req, res, next) => {
    const logger = new Logger('HTTP');
    logger.log(`${req.method} ${req.url} - ${req.ip}`);
    next();
  });

  // Configure rate limiting
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutos
      max: 100,
      skip: (req) => {
        // Skip rate limiting for video uploads
        return req.url?.includes('/videos/upload') || false;
      },
    }),
  );

  // Separate rate limit for video uploads (more lenient)
  app.use('/api/v1/videos/upload',
    rateLimit({
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 10, // 10 uploads per hour
    }),
  );

  // Extend timeout for file uploads
  app.use((req, res, next) => {
    if (req.url?.includes('/videos/upload')) {
      req.setTimeout(600000); // 10 minutes for request
      res.setTimeout(600000); // 10 minutes for response
      // Set specific headers for file uploads
      res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
    }
    next();
  });

  // Protección contra ataques XSS
  app.use((req, res, next) => {
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });

  // Protección contra ataques de clickjacking
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    next();
  });

  // Protección contra ataques de inyección de código
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
  });

  // Protección contra ataques de fuerza bruta
  app.use((req, res, next) => {
    res.setHeader(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains',
    );
    next();
  });

  app.use((req, res, next) => {
    res.setHeader('Accept', 'multipart/form-data');
    next();
  });

  const options = new DocumentBuilder()
    .setTitle('API Videoteca enfermería')
    .setDescription(
      'App para la gestión manuales de procedimientos en enfermería',
    )
    .setVersion('0.0.1')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, options);

  SwaggerModule.setup('/api/docs', app, document, {
    swaggerOptions: {
      filter: true,
    },
  });

  await app.listen(configService.app.port);

  logger.log(
    `${process.env.NODE_ENV === 'production' ? 'Production' : 'Development'} environment started successfully`,
  );
}

bootstrap();
