import { PartialType } from '@nestjs/mapped-types';
import { CreateVideoCommentDto } from './create-video-comment.dto';

export class UpdateVideoCommentDto extends PartialType(CreateVideoCommentDto) {}
