import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { Section } from './section.entity';

@Entity('manuals')
export class Manual {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({
    name: 'title',
    type: 'varchar',
    length: 255,
    unique: true,
    nullable: false,
    comment: 'Título del manual',
  })
  title: string;

  @OneToMany(() => Section, (section) => section.manual, {
    cascade: true,
    onDelete: 'CASCADE',
  })
  sections: Section[];

  @Column({
    name: 'created_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    comment: 'Fecha de creación del manual',
  })
  createdAt: Date;

  @Column({
    name: 'updated_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    onUpdate: 'CURRENT_TIMESTAMP',
    comment: 'Fecha de última actualización del manual',
  })
  updatedAt: Date;

  @Column({
    name: 'deleted_at',
    type: 'timestamp',
    nullable: true,
    default: null,
    comment: 'Fecha de eliminación del manual',
  })
  deletedAt: Date | null;
}
