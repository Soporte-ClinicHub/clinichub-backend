import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Block } from '../entities/block.entity';
import { Subsection } from '../entities/subsection.entity';
import { CreateBlockDto } from '../dto/create-block.dto';
import { ReorderBlocksDto } from '../dto/reorder-blocks.dto';

@Injectable()
export class BlockService {
  constructor(
    @InjectRepository(Block) private blockRepo: Repository<Block>,
    @InjectRepository(Subsection)
    private subsectionRepo: Repository<Subsection>,
  ) {}

  async createBlock(dto: CreateBlockDto) {
    const subsection = await this.subsectionRepo.findOneBy({
      id: dto.subsectionId,
    });
    if (!subsection) throw new NotFoundException('Subsection not found');
    
    // Si no se proporciona order, calcularlo automáticamente
    let order = dto.order;
    if (order === undefined || order === null) {
      const existingBlocksCount = await this.blockRepo.count({
        where: { subsection: { id: dto.subsectionId } }
      });
      order = existingBlocksCount;
    }
    
    const block = this.blockRepo.create({ 
      ...dto, 
      subsection,
      order 
    });
    return this.blockRepo.save(block);
  }

  async reorderBlocks(dto: ReorderBlocksDto) {
    const blocks = await this.blockRepo.find({
      where: { subsection: { id: dto.subsectionId } },
    });
    const blockMap = new Map(blocks.map((b) => [b.id, b]));
    for (const { id, order } of dto.blocks) {
      const block = blockMap.get(id);
      if (block) block.order = order;
    }
    await this.blockRepo.save(Array.from(blockMap.values()));
    // Retorna los bloques reordenados
    return this.blockRepo.find({
      where: { subsection: { id: dto.subsectionId } },
      order: { order: 'ASC' },
    });
  }

  async deleteBlock(id: string) {
    const block = await this.blockRepo.findOneBy({ id });
    if (!block) {
      throw new NotFoundException('Block not found');
    }
    return this.blockRepo.remove(block);
  }

  async updateBlock(id: string, updateData: { content?: string }) {
    const block = await this.blockRepo.findOneBy({ id });
    if (!block) {
      throw new NotFoundException('Block not found');
    }

    if (updateData.content !== undefined) {
      block.content = updateData.content;
    }

    return this.blockRepo.save(block);
  }
}
