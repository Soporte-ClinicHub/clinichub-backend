import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { Video } from '../../video/entities/video.entity';

@Entity('categories')
export class Category {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  name: string;

  @OneToMany(() => Video, (video) => video.category)
  videos: Video[];
}