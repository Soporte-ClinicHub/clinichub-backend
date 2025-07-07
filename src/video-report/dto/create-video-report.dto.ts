import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class CreateVideoReportDto {
  @IsUUID()
  @IsNotEmpty()
  userId: string;

  @IsUUID()
  @IsNotEmpty()
  videoId: string;

  @IsString()
  @IsNotEmpty()
  reason: string;
}
