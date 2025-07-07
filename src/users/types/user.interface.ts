import { UserRole } from '../../common/enums/user-role.enum';

export interface IUser {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  createdAt: Date;
  updatedAt: Date;
  deletedAt?: Date | null;
}
