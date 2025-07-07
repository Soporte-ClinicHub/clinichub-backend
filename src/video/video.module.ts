import { Module } from '@nestjs/common';
import { VideoService } from './video.service';
import { VideoController } from './video.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Video } from './entities/video.entity';
import { VideoStorageService } from './video-storage.service';
import { S3Module } from '../s3/s3.module';
import { Category } from '../category/entities/category.entity'; // Assuming Category is imported from the correct path

@Module({
  imports: [TypeOrmModule.forFeature([Video, Category]), S3Module],
  controllers: [VideoController],
  providers: [VideoService, VideoStorageService],
})
export class VideoModule {}
