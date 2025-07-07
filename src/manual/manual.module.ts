import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Manual } from './entities/manual.entity';
import { Section } from './entities/section.entity';
import { Subsection } from './entities/subsection.entity';
import { Block } from './entities/block.entity';
import { ManualService } from './services/manual.service';
import { ManualController } from './manual.controller';
import { SectionService } from './services/section.service';
import { SubsectionService } from './services/subsection.service';
import { BlockService } from './services/block.service';

@Module({
  imports: [TypeOrmModule.forFeature([Manual, Section, Subsection, Block])],
  controllers: [ManualController],
  providers: [ManualService, SectionService, SubsectionService, BlockService],
})
export class ManualModule {}
