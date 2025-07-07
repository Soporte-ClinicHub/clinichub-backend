import {
  Column,
  Entity,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Manual } from './manual.entity';
import { Subsection } from './subsection.entity';

@Entity('sections')
export class Section {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({
    name: 'title',
    type: 'varchar',
    length: 255,
    comment: 'Título de la sección del manual',
    unique: true,
  })
  title: string;

  @Column({
    name: 'order',
    type: 'int',
    nullable: false,
    comment: 'orden de la sección del manual',
  })
  order: number;

  @ManyToOne(() => Manual, (manual) => manual.sections, { onDelete: 'CASCADE' })
  manual: Manual;

  @OneToMany(() => Subsection, (subsection) => subsection.section, {
    cascade: true,
    onDelete: 'CASCADE',
  })
  subsections: Subsection[];

  @Column({
    name: 'created_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    comment: 'Fecha de creación de la sección',
  })
  createdAt: Date;

  @Column({
    name: 'updated_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    onUpdate: 'CURRENT_TIMESTAMP',
    comment: 'Fecha de última actualización de la sección',
  })
  updatedAt: Date;

  @Column({
    name: 'deleted_at',
    type: 'timestamp',
    nullable: true,
    default: null,
    comment: 'Fecha de eliminación de la sección',
  })
  deletedAt: Date | null;
}
