import { IsInt, isUUID,IsString, MaxLength, IsNotEmpty, IsUUID } from 'class-validator';

export class CreateVideoCommentDto {
  @IsUUID()
  @IsNotEmpty()
  userId: string;

  @IsUUID()
  @IsNotEmpty()
  videoId: string;

  @IsString()
  @MaxLength(1000)
  @IsNotEmpty()
  comment: string;
}
