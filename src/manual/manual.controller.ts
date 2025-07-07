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
import { BlockService } from './services/block.service';
import { CreateBlockDto } from './dto/create-block.dto';
import { CreateFullManualDto } from './dto/create-full-manual.dto';
import { CreateManualDto } from './dto/create-manual.dto';
import { CreateSectionDto } from './dto/create-section.dto';
import { CreateSubsectionDto } from './dto/create-subsection.dto';
import { ReorderBlocksDto } from './dto/reorder-blocks.dto';
import { ReorderSectionsDto } from './dto/reorder-sections.dto';
import { ReorderSubsectionsDto } from './dto/reorder-subsections.dto';
import { ManualService } from './services/manual.service';
import { SectionService } from './services/section.service';
import { SubsectionService } from './services/subsection.service';
import { ApiResponse } from 'src/common/types/ApiResponse.interface';
import { Manual } from './entities/manual.entity';

@UseGuards(JwtAuthGuard)
@Controller('manuals')
export class ManualController {
  constructor(
    private manualService: ManualService,
    private sectionService: SectionService,
    private subsectionService: SubsectionService,
    private blockService: BlockService,
  ) {}

  @Post()
  async createManual(
    @Body() dto: CreateManualDto,
  ): Promise<ApiResponse<Manual>> {
    try {
      const createdManual = await this.manualService.createManual(dto);
      return {
        statusCode: HttpStatus.CREATED,
        message: 'Manual created successfully',
        data: createdManual,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error creating manual',
        data: null,
      };
    }
  }

  @Post('section')
  async createSection(
    @Body() dto: CreateSectionDto,
  ): Promise<ApiResponse<any>> {
    try {
      const createdSection = await this.sectionService.createSection(dto);
      return {
        statusCode: HttpStatus.CREATED,
        message: 'Section created successfully',
        data: createdSection,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error creating section',
        data: null,
      };
    }
  }

  @Post('subsection')
  async createSubsection(
    @Body() dto: CreateSubsectionDto,
  ): Promise<ApiResponse<any>> {
    try {
      const createdSubsection =
        await this.subsectionService.createSubsection(dto);
      return {
        statusCode: HttpStatus.CREATED,
        message: 'Subsection created successfully',
        data: createdSubsection,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error creating subsection',
        data: null,
      };
    }
  }

  @Post('block')
  async createBlock(@Body() dto: CreateBlockDto): Promise<ApiResponse<any>> {
    try {
      const createdBlock = await this.blockService.createBlock(dto);
      return {
        statusCode: HttpStatus.CREATED,
        message: 'Block created successfully',
        data: createdBlock,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error creating block',
        data: null,
      };
    }
  }

  @Post('full')
  async createFullManual(
    @Body() dto: CreateFullManualDto,
  ): Promise<ApiResponse<any>> {
    try {
      const createdManual = await this.manualService.createFullManual(dto);
      return {
        statusCode: HttpStatus.CREATED,
        message: 'Full manual created successfully',
        data: createdManual,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error creating full manual',
        data: null,
      };
    }
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<ApiResponse<Manual>> {
    try {
      const manual = await this.manualService.findOne(id);
      if (!manual) {
        return {
          statusCode: HttpStatus.OK,
          message: 'Manual not found',
          data: null,
        };
      }
      return {
        statusCode: HttpStatus.OK,
        message: 'Manual retrieved successfully',
        data: manual,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error retrieving manual',
        data: null,
      };
    }
  }

  @Get()
  async getAll(): Promise<ApiResponse<Manual[]>> {
    try {
      const manuals = await this.manualService.getAllManuals();
      return {
        statusCode: HttpStatus.OK,
        message: 'Manuals retrieved successfully',
        data: manuals,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error retrieving manuals',
        data: null,
      };
    }
  }

  @Patch('block/reorder')
  async reorderBlocks(
    @Body() dto: ReorderBlocksDto,
  ): Promise<ApiResponse<any>> {
    try {
      const reorderedBlocks = await this.blockService.reorderBlocks(dto);
      return {
        statusCode: HttpStatus.OK,
        message: 'Blocks reordered successfully',
        data: reorderedBlocks,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error reordering blocks',
        data: null,
      };
    }
  }

  @Patch('section/reorder')
  async reorderSections(
    @Body() dto: ReorderSectionsDto,
  ): Promise<ApiResponse<any>> {
    try {
      const reorderedSections = await this.sectionService.reorderSections(dto);
      return {
        statusCode: HttpStatus.OK,
        message: 'Sections reordered successfully',
        data: reorderedSections,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error reordering sections',
        data: null,
      };
    }
  }

  @Patch('subsection/reorder')
  async reorderSubsections(
    @Body() dto: ReorderSubsectionsDto,
  ): Promise<ApiResponse<any>> {
    try {
      const reorderedSubsections =
        await this.subsectionService.reorderSubsections(dto);
      return {
        statusCode: HttpStatus.OK,
        message: 'Subsections reordered successfully',
        data: reorderedSubsections,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error reordering subsections',
        data: null,
      };
    }
  }

  // DELETE endpoints
  @Delete(':id')
  async deleteManual(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      await this.manualService.deleteManual(id);
      return {
        statusCode: HttpStatus.OK,
        message: 'Manual deleted successfully',
        data: null,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error deleting manual',
        data: null,
      };
    }
  }

  @Delete('section/:id')
  async deleteSection(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      await this.sectionService.deleteSection(id);
      return {
        statusCode: HttpStatus.OK,
        message: 'Section deleted successfully',
        data: null,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error deleting section',
        data: null,
      };
    }
  }

  @Delete('subsection/:id')
  async deleteSubsection(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      await this.subsectionService.deleteSubsection(id);
      return {
        statusCode: HttpStatus.OK,
        message: 'Subsection deleted successfully',
        data: null,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error deleting subsection',
        data: null,
      };
    }
  }

  @Delete('block/:id')
  async deleteBlock(@Param('id') id: string): Promise<ApiResponse<any>> {
    try {
      await this.blockService.deleteBlock(id);
      return {
        statusCode: HttpStatus.OK,
        message: 'Block deleted successfully',
        data: null,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error deleting block',
        data: null,
      };
    }
  }

  @Patch('section/:id')
  async updateSection(
    @Param('id') id: string,
    @Body() updateData: { title?: string },
  ): Promise<ApiResponse<any>> {
    try {
      const updatedSection = await this.sectionService.updateSection(id, updateData);
      return {
        statusCode: HttpStatus.OK,
        message: 'Section updated successfully',
        data: updatedSection,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error updating section',
        data: null,
      };
    }
  }

  @Patch('block/:id')
  async updateBlock(
    @Param('id') id: string,
    @Body() updateData: { content?: string },
  ): Promise<ApiResponse<any>> {
    try {
      const updatedBlock = await this.blockService.updateBlock(id, updateData);
      return {
        statusCode: HttpStatus.OK,
        message: 'Block updated successfully',
        data: updatedBlock,
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        message: error.message || 'Error updating block',
        data: null,
      };
    }
  }
}
