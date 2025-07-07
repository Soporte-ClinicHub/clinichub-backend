import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { VideoComment } from './entities/video-comment.entity';
import { VideoCommentController } from './video-comment.controller';
import { VideoCommentService } from './video-comment.service';

@Module({
  imports: [TypeOrmModule.forFeature([VideoComment])],
  controllers: [VideoCommentController],
  providers: [VideoCommentService],
  exports: [VideoCommentService],
})
export class VideoCommentModule {}
