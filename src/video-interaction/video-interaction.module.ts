import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { VideoInteraction } from './entities/video-interaction.entity';
import { VideoInteractionService } from './video-interaction.service';
import { VideoInteractionController } from './video-interaction.controller';

@Module({
  imports: [TypeOrmModule.forFeature([VideoInteraction])],
  controllers: [VideoInteractionController],
  providers: [VideoInteractionService],
  exports: [TypeOrmModule],
})
export class VideoInteractionModule {}
