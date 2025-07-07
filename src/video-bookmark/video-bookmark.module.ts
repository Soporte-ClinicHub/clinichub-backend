import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { VideoBookmark } from './entities/video-bookmark.entity';
import { VideoBookmarkService } from './video-bookmark.service';
import { VideoBookmarkController } from './video-bookmark.controller';

@Module({
  imports: [TypeOrmModule.forFeature([VideoBookmark])],
  controllers: [VideoBookmarkController],
  providers: [VideoBookmarkService],
  exports: [TypeOrmModule],
})
export class VideoBookmarkModule {}
