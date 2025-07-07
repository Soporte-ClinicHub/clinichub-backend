import {
  IsUUID,
  IsNotEmpty,
  IsArray,
  ArrayNotEmpty,
  ValidateNested,
  IsInt,
} from 'class-validator';
import { Type } from 'class-transformer';

class SectionOrderDto {
  @IsUUID('4')
  @IsNotEmpty()
  id: string;

  @IsInt()
  @IsNotEmpty()
  order: number;
}

export class ReorderSectionsDto {
  @IsUUID('4')
  @IsNotEmpty()
  manualId: string;

  @IsArray()
  @ArrayNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => SectionOrderDto)
  sections: SectionOrderDto[];
}
