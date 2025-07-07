import { IUser } from '../../users/types/user.interface';
import { IVideo } from '../../video/types/video.interface';

export interface IVideoComment {
  id: string;
  user: IUser;
  video: IVideo;
  comment: string;
  createdAt: Date;
  updatedAt: Date;
  deletedAt?: Date | null;
}
