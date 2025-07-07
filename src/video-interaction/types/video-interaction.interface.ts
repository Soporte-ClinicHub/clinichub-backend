import { IUser } from '../../users/types/user.interface';
import { IVideo } from '../../video/types/video.interface';
import { VideoInteractionType } from '../enum/video-interaction.enums';

export interface IVideoInteraction {
  id: string;
  user: IUser;
  video: IVideo;
  type: VideoInteractionType;
  reportReason?: string;
  createdAt: Date;
}
