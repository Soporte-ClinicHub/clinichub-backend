import { IUser } from '../../users/types/user.interface';

export interface IVideo {
  id: string;
  title: string;
  description: string;
  fileKey: string;
  fileUrl: string;
  contentType: string;
  fileSize: number;
  uploadDuration: number;
  createdAt: Date;
  updatedAt: Date;
  deletedAt?: Date | null;
  user: IUser;
}
