import {
  Body,
  Controller,
  Delete,
  Get,
  HttpStatus,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CreateVideoBookmarkDto } from './dto/create-video-bookmark.dto';
import { UpdateVideoBookmarkDto } from './dto/update-video-bookmark.dto';
import { VideoBookmarkService } from './video-bookmark.service';
import { ApiResponse } from 'src/common/types/ApiResponse.interface';

@Controller('video-bookmarks')
@UseGuards(JwtAuthGuard)
export class VideoBookmarkController {
  constructor(private readonly service: VideoBookmarkService) {}

  @Post()
  async create(@Body() dto: CreateVideoBookmarkDto): Promise<ApiResponse<any>> {
    try {
      const bookmark = await this.service.create(dto);
      return {
        statusCode: HttpStatus.CREATED,
        message: 'Marcador creado exitosamente',
        data: bookmark,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error creando el marcador',
        data: null,
      };
    }
  }

  @Get()
  async findAll(): Promise<ApiResponse<any[]>> {
    try {
      const bookmarks = await this.service.findAll();
      return {
        statusCode: HttpStatus.OK,
        message: 'Marcadores obtenidos exitosamente',
        data: bookmarks,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error obteniendo los marcadores',
        data: null,
      };
    }
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      const bookmark = await this.service.findOne(id);
      if (!bookmark) {
        return {
          statusCode: HttpStatus.OK,
          message: 'Marcador no encontrado',
          data: null,
        };
      }
      return {
        statusCode: HttpStatus.OK,
        message: 'Marcador obtenido exitosamente',
        data: bookmark,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error obteniendo el marcador',
        data: null,
      };
    }
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateVideoBookmarkDto,
  ): Promise<ApiResponse<any>> {
    try {
      const updated = await this.service.update(id, dto);
      return {
        statusCode: HttpStatus.OK,
        message: 'Marcador actualizado exitosamente',
        data: updated,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error actualizando el marcador',
        data: null,
      };
    }
  }

  @Delete(':id')
  async remove(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      const deleted = await this.service.remove(id);
      return {
        statusCode: HttpStatus.OK,
        message: 'Marcador eliminado exitosamente',
        data: deleted,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error eliminando el marcador',
        data: null,
      };
    }
  }
}
