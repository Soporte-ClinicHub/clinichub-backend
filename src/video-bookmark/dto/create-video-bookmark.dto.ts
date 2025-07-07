import {
  IsUUID,
  IsString,
  MaxLength,
  IsNotEmpty,
  IsEnum,
} from 'class-validator';
import { BookmarkType } from '../enum/bookmark-type.enum';

export class CreateVideoBookmarkDto {
  @IsUUID()
  @IsNotEmpty()
  userId: string;

  @IsUUID()
  @IsNotEmpty()
  videoId: string;

  @IsEnum(BookmarkType)
  @IsNotEmpty()
  bookmarkType: BookmarkType;

  @IsString()
  @MaxLength(255)
  @IsNotEmpty()
  note: string;

  @IsNotEmpty()
  position: number;
}
