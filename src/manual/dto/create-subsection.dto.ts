import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class CreateSubsectionDto {
  @IsNotEmpty()
  @IsString()
  title: string;

  @IsUUID('4')
  @IsNotEmpty()
  sectionId: string;
}
