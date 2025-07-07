import {
  IsArray,
  IsNotEmpty,
  IsUUID,
  ValidateNested,
  ArrayNotEmpty,
  IsInt,
} from 'class-validator';
import { Type } from 'class-transformer';

class BlockOrderDto {
  @IsUUID('4')
  @IsNotEmpty()
  id: string;

  @IsInt()
  @IsNotEmpty()
  order: number;
}

export class ReorderBlocksDto {
  @IsUUID('4')
  @IsNotEmpty()
  subsectionId: string;

  @IsArray()
  @ArrayNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => BlockOrderDto)
  blocks: BlockOrderDto[];
}
