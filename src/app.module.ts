import { Module } from '@nestjs/common';

import { AuthModule } from './auth/auth.module';
import { CategoryModule } from './category/category.module';
import { ConfigModule } from './config/config.module';
import { DatabaseModule } from './database/database.module';
import { FirebaseModule } from './firebase/firebase.module';
import { HealthModule } from './health/health.module';
import { JwtModule } from './jwt/jwt.module';
import { ManualModule } from './manual/manual.module';
import { S3Module } from './s3/s3.module';
import { UsersModule } from './users/users.module';
import { VideoBookmarkModule } from './video-bookmark/video-bookmark.module';
import { VideoCommentModule } from './video-comment/video-comment.module';
import { VideoInteractionModule } from './video-interaction/video-interaction.module';
import { VideoReportModule } from './video-report/video-report.module';
import { VideoModule } from './video/video.module';

@Module({
  imports: [
    ConfigModule,
    HealthModule,
    DatabaseModule,
    S3Module,
    JwtModule,
    FirebaseModule,
    UsersModule,
    AuthModule,
    VideoModule,
    ManualModule,
    VideoInteractionModule,
    VideoCommentModule,
    VideoReportModule,
    VideoBookmarkModule,
    CategoryModule,
  ],
})
export class AppModule {}
