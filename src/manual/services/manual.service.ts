import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manual } from '../entities/manual.entity';
import { CreateManualDto } from '../dto/create-manual.dto';
import { CreateFullManualDto } from '../dto/create-full-manual.dto';
import { Section } from '../entities/section.entity';
import { Subsection } from '../entities/subsection.entity';
import { Block } from '../entities/block.entity';
import { BlockType } from '../enums/block-type.enum';

@Injectable()
export class ManualService {
  constructor(
    @InjectRepository(Manual) private manualRepo: Repository<Manual>,
  ) {}

  async createManual(dto: CreateManualDto) {
    const manual = this.manualRepo.create(dto);
    return this.manualRepo.save(manual);
  }

  async getAllManuals() {
    return this.manualRepo.find({
      relations: {
        sections: {
          subsections: {
            blocks: true,
          },
        },
      },
    });
  }

  async findOne(id: string) {
    return this.manualRepo.findOne({
      where: { id },
      relations: {
        sections: {
          subsections: {
            blocks: true,
          },
        },
      },
    });
  }

  async deleteManual(id: string) {
    const manual = await this.manualRepo.findOneBy({ id });
    if (!manual) {
      throw new Error('Manual not found');
    }
    return this.manualRepo.remove(manual);
  }

  async createFullManual(dto: CreateFullManualDto) {
    const manual = this.manualRepo.create({ title: dto.title });
    if (dto.sections) {
      manual.sections = dto.sections.map((sectionDto) => {
        const section = new Section();
        section.title = sectionDto.title;
        section.order = sectionDto.order;
        if (sectionDto.subsections) {
          section.subsections = sectionDto.subsections.map((subsectionDto) => {
            const subsection = new Subsection();
            subsection.title = subsectionDto.title;
            subsection.order = subsectionDto.order;
            if (subsectionDto.blocks) {
              subsection.blocks = subsectionDto.blocks.map((blockDto) => {
                const block = new Block();
                block.type = blockDto.type;
                block.content = blockDto.content;
                block.order = blockDto.order;
                return block;
              });
            }
            return subsection;
          });
        }
        return section;
      });
    }
    return this.manualRepo.save(manual);
  }
}
