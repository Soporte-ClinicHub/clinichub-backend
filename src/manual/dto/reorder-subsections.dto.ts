import {
  IsUUID,
  IsNotEmpty,
  IsArray,
  ArrayNotEmpty,
  ValidateNested,
  IsInt,
} from 'class-validator';
import { Type } from 'class-transformer';

class SubsectionOrderDto {
  @IsUUID('4')
  @IsNotEmpty()
  id: string;

  @IsInt()
  @IsNotEmpty()
  order: number;
}

export class ReorderSubsectionsDto {
  @IsUUID('4')
  @IsNotEmpty()
  sectionId: string;

  @IsArray()
  @ArrayNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => SubsectionOrderDto)
  subsections: SubsectionOrderDto[];
}
