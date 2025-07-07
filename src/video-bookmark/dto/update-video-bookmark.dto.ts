import { PartialType } from '@nestjs/mapped-types';
import { CreateVideoBookmarkDto } from './create-video-bookmark.dto';

export class UpdateVideoBookmarkDto extends PartialType(CreateVideoBookmarkDto) {}
