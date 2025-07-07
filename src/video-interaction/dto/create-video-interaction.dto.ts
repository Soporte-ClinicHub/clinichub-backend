import { IsEnum, IsNotEmpty, IsUUID } from 'class-validator';
import { VideoInteractionType } from '../enum/video-interaction.enums';

export class CreateVideoInteractionDto {
  @IsUUID()
  @IsNotEmpty()
  userId: string;

  @IsUUID()
  @IsNotEmpty()
  videoId: string;

  @IsEnum(VideoInteractionType)
  @IsNotEmpty()
  type: VideoInteractionType;
}
