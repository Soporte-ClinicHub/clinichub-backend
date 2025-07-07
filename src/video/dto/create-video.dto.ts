import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsUUID, IsString } from 'class-validator';

export class CreateVideoDto {
  @ApiProperty({
    description: 'Título del video',
    example: 'Procedimiento de enfermería: Lavado de manos',
  })
  @IsNotEmpty()
  @IsString()
  title: string;

  @ApiProperty({
    description: 'Descripción del video',
    example:
      'Este video muestra el procedimiento correcto para el lavado de manos clínico',
    required: false,
  })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiProperty({
    description: 'ID de la categoría seleccionada',
    example: 'fbbe7622-03a5-4b49-8db3-22a2061ccae1',
    required: false,
  })
  @IsOptional()
  @IsUUID()
  categoryId?: string;

  @ApiProperty({
    description: 'Nombre de nueva categoría si no se selecciona una existente',
    example: 'Cuidados intensivos',
    required: false,
  })
  @IsOptional()
  @IsString()
  newCategory?: string;
}
