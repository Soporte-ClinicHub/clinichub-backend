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
import { CreateVideoReportDto } from './dto/create-video-report.dto';
import { VideoReportService } from './video-report.service';
import { ApiResponse } from 'src/common/types/ApiResponse.interface';

@UseGuards(JwtAuthGuard)
@Controller('video-reports')
export class VideoReportController {
  constructor(private readonly videoReportService: VideoReportService) {}

  @Post()
  async create(
    @Body() createDto: CreateVideoReportDto,
  ): Promise<ApiResponse<any>> {
    try {
      const report = await this.videoReportService.create(createDto);
      return {
        statusCode: HttpStatus.CREATED,
        message: 'Reporte creado exitosamente',
        data: report,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error creando el reporte',
        data: null,
      };
    }
  }

  @Get()
  async findAll(): Promise<ApiResponse<any[]>> {
    try {
      const reports = await this.videoReportService.findAll();
      return {
        statusCode: HttpStatus.OK,
        message: 'Reportes obtenidos exitosamente',
        data: reports,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error obteniendo los reportes',
        data: null,
      };
    }
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      const report = await this.videoReportService.findOne(id);
      if (!report) {
        return {
          statusCode: HttpStatus.OK,
          message: 'Reporte no encontrado',
          data: null,
        };
      }
      return {
        statusCode: HttpStatus.OK,
        message: 'Reporte obtenido exitosamente',
        data: report,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error obteniendo el reporte',
        data: null,
      };
    }
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body() updateDto: Partial<CreateVideoReportDto>,
  ): Promise<ApiResponse<any>> {
    try {
      const updated = await this.videoReportService.update(id, updateDto);
      return {
        statusCode: HttpStatus.OK,
        message: 'Reporte actualizado exitosamente',
        data: updated,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error actualizando el reporte',
        data: null,
      };
    }
  }

  @Delete(':id')
  async remove(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      const deleted = await this.videoReportService.remove(id);
      return {
        statusCode: HttpStatus.OK,
        message: 'Reporte eliminado exitosamente',
        data: deleted,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error eliminando el reporte',
        data: null,
      };
    }
  }
}
