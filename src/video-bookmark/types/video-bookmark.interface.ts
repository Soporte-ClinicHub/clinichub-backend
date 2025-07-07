import { IUser } from '../../users/types/user.interface';
import { IVideo } from '../../video/types/video.interface';
import { BookmarkType } from '../enum/bookmark-type.enum';

export interface IVideoBookmark {
  id: string;
  user: IUser;
  video: IVideo;
  bookmarkType: BookmarkType;
  note?: string;
  position?: number;
  createdAt: Date;
}
