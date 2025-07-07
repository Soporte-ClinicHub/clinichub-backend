import {
  IsString,
  IsArray,
  IsOptional,
  IsEnum,
  IsInt,
  ValidateNested,
  IsNotEmpty,
} from 'class-validator';
import { Type } from 'class-transformer';
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
}

export class CreateSubsectionDto {
  @IsString()
  @IsNotEmpty()
  title: string;

  @IsInt()
  @IsNotEmpty()
  order: number;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateBlockDto)
  blocks?: CreateBlockDto[];
}

export class CreateSectionDto {
  @IsString()
  @IsNotEmpty()
  title: string;

  @IsInt()
  @IsNotEmpty()
  order: number;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateSubsectionDto)
  subsections?: CreateSubsectionDto[];
}

export class CreateBlockInFullManualDto {
  @IsEnum(BlockType)
  @IsNotEmpty()
  type: BlockType;

  @IsString()
  @IsNotEmpty()
  content: string;

  @IsInt()
  @IsNotEmpty()
  order: number;
}

export class CreateSubsectionInFullManualDto {
  @IsString()
  @IsNotEmpty()
  title: string;

  @IsInt()
  @IsNotEmpty()
  order: number;

  @ValidateNested({ each: true })
  @Type(() => CreateBlockInFullManualDto)
  blocks?: CreateBlockInFullManualDto[];
}

export class CreateSectionInFullManualDto {
  @IsString()
  @IsNotEmpty()
  title: string;

  @IsInt()
  @IsNotEmpty()
  order: number;

  @ValidateNested({ each: true })
  @Type(() => CreateSubsectionInFullManualDto)
  subsections?: CreateSubsectionInFullManualDto[];
}

export class CreateFullManualDto {
  @IsString()
  @IsNotEmpty()
  title: string;

  @ValidateNested({ each: true })
  @Type(() => CreateSectionInFullManualDto)
  sections?: CreateSectionInFullManualDto[];
}
