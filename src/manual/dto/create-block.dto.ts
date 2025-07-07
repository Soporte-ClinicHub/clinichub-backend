import { IsEnum, IsInt, IsNotEmpty, IsString, IsUUID } from 'class-validator';
import { BlockType } from '../enums/block-type.enum';

export class CreateBlockDto {
  @IsEnum(BlockType)
  @IsNotEmpty()
  type: BlockType;

  @IsString()
  @IsNotEmpty()
  content: string;

  @IsInt()
  @IsNotEmpty()
  order: number;

  @IsString()
  @IsUUID('4')
  @IsNotEmpty()
  subsectionId: string;
}
