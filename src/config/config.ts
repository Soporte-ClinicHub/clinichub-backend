import { registerAs } from '@nestjs/config';

export default registerAs('config', () => {
  return {
    app: {
      port: parseInt(process.env.APP_PORT, 10) || 3000,
      environment: process.env.NODE_ENV || 'development',
    },
    postgres: {
      dbName: process.env.POSTGRES_DB,
      port: parseInt(process.env.POSTGRES_PORT, 10),
      password: process.env.POSTGRES_PASSWORD,
      user: process.env.POSTGRES_USER,
      host: process.env.POSTGRES_HOST,
    },
    jwt: {
      accessSecret: process.env.ACCESS_JWT_SECRET,
      refreshSecret: process.env.REFRESH_JWT_SECRET,
      accessExpiresIn: process.env.ACCESS_EXPIRES_IN,
      refreshExpiresIn: process.env.REFRESH_EXPIRES_IN,
    },
    aws: {
      region: process.env.AWS_REGION,
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      s3: {
        bucketName: process.env.AWS_S3_BUCKET_NAME,
      },
    },
    firebase: {
      projectId: process.env.FIREBASE_PROJECT_ID,
      privateKey: process.env.FIREBASE_PRIVATE_KEY
        ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
        : undefined,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    },
  };
});
