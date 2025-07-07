import { IUser } from '../../users/types/user.interface';
import { IVideo } from '../../video/types/video.interface';
import { VideoReportStatus } from '../enum/video-report-status.enum';

export interface IVideoReport {
  id: string;
  user: IUser;
  video: IVideo;
  reason: string;
  status: VideoReportStatus;
  createdAt: Date;
  updatedAt: Date;
  deletedAt?: Date | null;
}
