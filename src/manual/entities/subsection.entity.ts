import {
  Column,
  Entity,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Block } from './block.entity';
import { Section } from './section.entity';

@Entity('subsections')
export class Subsection {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({
    name: 'title',
    type: 'varchar',
    length: 255,
    comment: 'Título de la subsección del manual',
    unique: true,
  })
  title: string;

  @Column({
    name: 'order',
    type: 'text',
    nullable: true,
    comment: 'Orden de la subsección del manual',
  })
  order: number;

  @ManyToOne(() => Section, (section) => section.subsections, {
    onDelete: 'CASCADE',
  })
  section: Section;

  @OneToMany(() => Block, (block) => block.subsection, {
    cascade: true,
    onDelete: 'CASCADE',
  })
  blocks: Block[];

  @Column({
    name: 'created_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    comment: 'Fecha de creación de la subsección',
  })
  createdAt: Date;

  @Column({
    name: 'updated_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    onUpdate: 'CURRENT_TIMESTAMP',
    comment: 'Fecha de última actualización de la subsección',
  })
  updatedAt: Date;

  @Column({
    name: 'deleted_at',
    type: 'timestamp',
    nullable: true,
    default: null,
    comment: 'Fecha de eliminación de la subsección',
  })
  deletedAt: Date | null;
}
