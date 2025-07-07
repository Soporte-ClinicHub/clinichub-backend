import { IsNotEmpty, IsString } from 'class-validator';

export class CreateManualDto {
  @IsNotEmpty()
  @IsString()
  title: string;
}
