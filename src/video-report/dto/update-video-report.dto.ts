import { IsEnum, IsNotEmpty } from 'class-validator';
import { VideoReportStatus } from '../enum/video-report-status.enum';

export class UpdateVideoReportDto {
  @IsEnum(VideoReportStatus)
  @IsNotEmpty()
  status: VideoReportStatus;
}
