import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Section } from '../entities/section.entity';
import { Manual } from '../entities/manual.entity';
import { CreateSectionDto } from '../dto/create-section.dto';
import { ReorderSectionsDto } from '../dto/reorder-sections.dto';

@Injectable()
export class SectionService {
  constructor(
    @InjectRepository(Section) private sectionRepo: Repository<Section>,
    @InjectRepository(Manual) private manualRepo: Repository<Manual>,
  ) {}

  async createSection(dto: CreateSectionDto) {
    const manual = await this.manualRepo.findOneBy({ id: dto.manualId });
    if (!manual) throw new NotFoundException('Manual not found');
    
    // Calcular el orden automáticamente
    const existingSectionsCount = await this.sectionRepo.count({
      where: { manual: { id: dto.manualId } }
    });
    
    const section = this.sectionRepo.create({ 
      title: dto.title, 
      manual,
      order: existingSectionsCount
    });
    return this.sectionRepo.save(section);
  }

  async reorderSections(dto: ReorderSectionsDto) {
    const sections = await this.sectionRepo.find({
      where: { manual: { id: dto.manualId } },
    });
    const sectionMap = new Map(sections.map((s) => [s.id, s]));
    for (const { id, order } of dto.sections) {
      const section = sectionMap.get(id);
      if (section) {
        section.order = order;
      }
    }
    await this.sectionRepo.save(Array.from(sectionMap.values()));
    const updatedSections = await this.sectionRepo.find({
      where: { manual: { id: dto.manualId } },
      order: { order: 'ASC' },
    });
    return updatedSections;
  }

  async deleteSection(id: string) {
    const section = await this.sectionRepo.findOneBy({ id });
    if (!section) {
      throw new NotFoundException('Section not found');
    }
    return this.sectionRepo.remove(section);
  }

  async updateSection(id: string, updateData: { title?: string }) {
    const section = await this.sectionRepo.findOneBy({ id });
    if (!section) {
      throw new NotFoundException('Section not found');
    }

    if (updateData.title) {
      section.title = updateData.title;
    }

    return this.sectionRepo.save(section);
  }
}
