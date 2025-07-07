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
import { CreateVideoCommentDto } from './dto/create-video-comment.dto';
import { UpdateVideoCommentDto } from './dto/update-video-comment.dto';
import { VideoCommentService } from './video-comment.service';
import { ApiResponse } from 'src/common/types/ApiResponse.interface';

@UseGuards(JwtAuthGuard)
@Controller('video-comments')
export class VideoCommentController {
  constructor(private readonly service: VideoCommentService) {}

  @Post()
  async create(@Body() dto: CreateVideoCommentDto): Promise<ApiResponse<any>> {
    try {
      const comment = await this.service.create(dto);
      return {
        statusCode: HttpStatus.CREATED,
        message: 'Comentario creado exitosamente',
        data: comment,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error creando el comentario',
        data: null,
      };
    }
  }

  @Get()
  async findAll(): Promise<ApiResponse<any[]>> {
    try {
      const comments = await this.service.findAll();
      return {
        statusCode: HttpStatus.OK,
        message: 'Comentarios obtenidos exitosamente',
        data: comments,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error obteniendo los comentarios',
        data: null,
      };
    }
  }

  // Agregar endpoint para obtener comentarios por videoId
  @Get('video/:videoId')
  async findByVideoId(@Param('videoId') videoId: string): Promise<ApiResponse<any[]>> {
    try {
      const comments = await this.service.findByVideoId(videoId);
      return {
        statusCode: HttpStatus.OK,
        message: 'Comentarios obtenidos exitosamente',
        data: comments,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error obteniendo los comentarios',
        data: null,
      };
    }
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      const comment = await this.service.findOne(id);
      if (!comment) {
        return {
          statusCode: HttpStatus.OK,
          message: 'Comentario no encontrado',
          data: null,
        };
      }
      return {
        statusCode: HttpStatus.OK,
        message: 'Comentario obtenido exitosamente',
        data: comment,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error obteniendo el comentario',
        data: null,
      };
    }
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateVideoCommentDto,
  ): Promise<ApiResponse<any>> {
    try {
      const updated = await this.service.update(id, dto);
      return {
        statusCode: HttpStatus.OK,
        message: 'Comentario actualizado exitosamente',
        data: updated,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error actualizando el comentario',
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
        message: 'Comentario eliminado exitosamente',
        data: deleted,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error eliminando el comentario',
        data: null,
      };
    }
  }
}