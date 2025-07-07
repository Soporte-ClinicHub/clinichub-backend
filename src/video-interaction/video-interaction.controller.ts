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
import {
  ApiOperation,
  ApiTags,
  ApiResponse as SwaggerApiResponse,
} from '@nestjs/swagger';
import { ApiResponse } from 'src/common/types/ApiResponse.interface';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CreateVideoInteractionDto } from './dto/create-video-interaction.dto';
import { UpdateVideoInteractionDto } from './dto/update-video-interaction.dto';
import { VideoInteraction } from './entities/video-interaction.entity';
import { VideoInteractionService } from './video-interaction.service';

@ApiTags('video-interactions')
@UseGuards(JwtAuthGuard)
@Controller('video-interactions')
export class VideoInteractionController {
  constructor(
    private readonly videoInteractionService: VideoInteractionService,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Crear interacción de video' })
  @SwaggerApiResponse({
    status: 201,
    description: 'Interacción de video creada.',
  })
  async create(
    @Body() createDto: CreateVideoInteractionDto,
  ): Promise<ApiResponse<VideoInteraction>> {
    try {
      console.log('Creating Video Interaction:', createDto);
      const data = await this.videoInteractionService.create(createDto);
      console.log('Video Interaction Created:', data);
      return {
        message: 'Interacción de video creada',
        statusCode: HttpStatus.CREATED,
        data,
      };
    } catch (error) {
      return {
        message: error.message || 'Error al crear la interacción de video',
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        data: null,
      };
    }
  }

  @Get()
  @ApiOperation({ summary: 'Listar interacciones de video' })
  @SwaggerApiResponse({
    status: 200,
    description: 'Lista de interacciones de video.',
  })
  async findAll(): Promise<ApiResponse<any[]>> {
    try {
      const data = await this.videoInteractionService.findAll();
      return {
        message: 'Lista de interacciones de video',
        statusCode: HttpStatus.OK,
        data,
      };
    } catch (error) {
      return {
        message: error.message || 'Error al listar interacciones de video',
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        data: null,
      };
    }
  }

  @Get(':id')
  @ApiOperation({ summary: 'Obtener interacción de video por id' })
  @SwaggerApiResponse({
    status: 200,
    description: 'Interacción de video encontrada.',
  })
  async findOne(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      const data = await this.videoInteractionService.findOne(id);
      if (!data) {
        return {
          message: 'Interacción de video no encontrada',
          statusCode: HttpStatus.OK,
          data: null,
        };
      }
      return {
        message: 'Interacción de video encontrada',
        statusCode: HttpStatus.OK,
        data,
      };
    } catch (error) {
      return {
        message: error.message || 'Error al buscar la interacción de video',
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        data: null,
      };
    }
  }

  @Get('video/:videoId/user/:userId')
  @ApiOperation({ summary: 'Obtener interacciones por video y usuario' })
  @SwaggerApiResponse({
    status: 200,
    description: 'Interacciones de video por usuario.',
  })
  async findByUserAndVideo(
    @Param('videoId') videoId: string,
    @Param('userId') userId: string,
  ): Promise<ApiResponse<any[]>> {
    try {
      const data = await this.videoInteractionService.findByUserAndVideo(
        userId,
        videoId,
      );
      return {
        message: 'Interacciones obtenidas exitosamente',
        statusCode: HttpStatus.OK,
        data,
      };
    } catch (error) {
      return {
        message: error.message || 'Error al buscar interacciones',
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        data: null,
      };
    }
  }

  @Get('video/:videoId')
  @ApiOperation({ summary: 'Obtener interacciones por video' })
  @SwaggerApiResponse({
    status: 200,
    description: 'Interacciones de video obtenidas.',
  })
  async findByVideoId(videoId: string): Promise<ApiResponse<any[]>> {
    try {
      const data = await this.videoInteractionService.findByVideoId(videoId);
      return {
        message: 'Interacciones de video obtenidas exitosamente',
        statusCode: HttpStatus.OK,
        data,
      };
    } catch (error) {
      return {
        message: error.message || 'Error al buscar interacciones de video',
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        data: null,
      };
    }
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Actualizar interacción de video' })
  @SwaggerApiResponse({
    status: 200,
    description: 'Interacción de video actualizada.',
  })
  async update(
    @Param('id') id: string,
    @Body() updateDto: UpdateVideoInteractionDto,
  ): Promise<ApiResponse<any>> {
    try {
      const data = await this.videoInteractionService.update(id, updateDto);
      return {
        message: 'Interacción de video actualizada',
        statusCode: HttpStatus.OK,
        data,
      };
    } catch (error) {
      return {
        message: error.message || 'Error al actualizar la interacción de video',
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        data: null,
      };
    }
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Eliminar interacción de video' })
  @SwaggerApiResponse({
    status: 200,
    description: 'Interacción de video eliminada.',
  })
  async remove(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      const data = await this.videoInteractionService.remove(id);
      return {
        message: 'Interacción de video eliminada',
        statusCode: HttpStatus.OK,
        data,
      };
    } catch (error) {
      return {
        message: error.message || 'Error al eliminar la interacción de video',
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        data: null,
      };
    }
  }
}
