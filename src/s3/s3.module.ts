import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { S3Service } from './s3.service';
import { S3Client } from '@aws-sdk/client-s3';
import config from '../config/config';

@Module({
  imports: [ConfigModule.forFeature(config)],
  providers: [
    S3Service,
    {
      provide: 'S3_CLIENT',
      useFactory: (configService) => {
        return new S3Client({
          region: configService.aws.region,
          credentials: {
            accessKeyId: configService.aws.accessKeyId,
            secretAccessKey: configService.aws.secretAccessKey,
          },
        });
      },
      inject: [config.KEY],
    },
  ],
  exports: [S3Service, 'S3_CLIENT'],
})
export class S3Module {}
