import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Subsection } from '../entities/subsection.entity';
import { Section } from '../entities/section.entity';
import { CreateSubsectionDto } from '../dto/create-subsection.dto';
import { ReorderSubsectionsDto } from '../dto/reorder-subsections.dto';

@Injectable()
export class SubsectionService {
  constructor(
    @InjectRepository(Subsection)
    private subsectionRepo: Repository<Subsection>,
    @InjectRepository(Section) private sectionRepo: Repository<Section>,
  ) {}

  async createSubsection(dto: CreateSubsectionDto) {
    const section = await this.sectionRepo.findOneBy({ id: dto.sectionId });
    if (!section) throw new NotFoundException('Section not found');
    
    // Calcular el orden automáticamente
    const existingSubsectionsCount = await this.subsectionRepo.count({
      where: { section: { id: dto.sectionId } }
    });
    
    const subsection = this.subsectionRepo.create({
      title: dto.title,
      section,
      order: existingSubsectionsCount
    });
    return this.subsectionRepo.save(subsection);
  }

  async reorderSubsections(dto: ReorderSubsectionsDto) {
    const subsections = await this.subsectionRepo.find({
      where: { section: { id: dto.sectionId } },
    });
    const subsectionMap = new Map(subsections.map((s) => [s.id, s]));
    for (const { id, order } of dto.subsections) {
      const subsection = subsectionMap.get(id);
      if (subsection) {
        subsection.order = order;
      }
    }
    await this.subsectionRepo.save(Array.from(subsectionMap.values()));
    const updatedSubsections = await this.subsectionRepo.find({
      where: { section: { id: dto.sectionId } },
      order: { order: 'ASC' },
    });
    return updatedSubsections;
  }

  async deleteSubsection(id: string) {
    const subsection = await this.subsectionRepo.findOneBy({ id });
    if (!subsection) {
      throw new NotFoundException('Subsection not found');
    }
    return this.subsectionRepo.remove(subsection);
  }
}
