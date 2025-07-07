import {
  Column,
  CreateDateColumn,
  DeleteDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { Category } from '../../category/entities/category.entity';

@Entity('videos')
export class Video {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({
    name: 'title',
    type: 'varchar',
    length: 255,
    nullable: false,
    comment: 'Título del video',
  })
  title: string;

  @Column({
    name: 'description',
    type: 'text',
    nullable: true,
    comment: 'Descripción del video',
  })
  description: string;

  @ManyToOne(() => Category, (category) => category.videos, { nullable: true })
  @JoinColumn({ name: 'category_id' })
  category?: Category;

  @Column({
    name: 'category_id',
    type: 'uuid',
    nullable: true,
    comment: 'ID de la categoría asociada',
  })
  categoryId?: string;

  @Column({
    name: 'file_key',
    type: 'varchar',
    length: 255,
    nullable: false,
    comment: 'Clave del archivo en S3',
  })
  fileKey: string;

  @Column({
    name: 'file_url',
    type: 'varchar',
    length: 255,
    nullable: false,
    comment: 'URL del archivo en S3',
  })
  fileUrl: string;

  @Column({
    name: 'content_type',
    type: 'varchar',
    length: 100,
    nullable: false,
    comment: 'Tipo de contenido del archivo',
  })
  contentType: string;

  @Column({
    name: 'file_size',
    type: 'integer',
    nullable: true,
    comment: 'Tamaño del archivo en bytes',
  })
  fileSize: number;

  @Column({
    name: 'upload_duration',
    type: 'integer',
    nullable: false,
    default: 0,
    comment: 'Duración de la subida en segundos',
  })
  uploadDuration: number;

  @CreateDateColumn({
    name: 'created_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    comment: 'Fecha de creación del registro',
  })
  createdAt: Date;

  @UpdateDateColumn({
    name: 'updated_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    onUpdate: 'CURRENT_TIMESTAMP',
    comment: 'Fecha de última actualización del registro',
  })
  updatedAt: Date;

  @DeleteDateColumn({
    name: 'deleted_at',
    type: 'timestamp',
    nullable: true,
    default: null,
    comment: 'Fecha de eliminación del registro',
  })
  deletedAt: Date;
}
