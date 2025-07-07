import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class CreateSectionDto {
  @IsNotEmpty()
  @IsString()
  title: string;

  @IsUUID('4')
  @IsNotEmpty()
  manualId: string;
}
