import { Module } from '@nestjs/common';
import { ConfigModule as NestConfig } from '@nestjs/config';

import config from './config';
import environmentSchema from './schemas/env-validation-schema';

@Module({
  imports: [
    NestConfig.forRoot({
      envFilePath:
        process.env.NODE_ENV === 'production' ? '.env.prod' : '.env.dev',
      load: [config],
      isGlobal: true,
      validationSchema: environmentSchema,
    }),
  ],
})
export class ConfigModule {}
