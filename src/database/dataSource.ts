import { VideoBookmark } from '../video-bookmark/entities/video-bookmark.entity';
import { DataSource, DataSourceOptions } from 'typeorm';
import { Block } from '../manual/entities/block.entity';
import { Manual } from '../manual/entities/manual.entity';
import { Section } from '../manual/entities/section.entity';
import { Subsection } from '../manual/entities/subsection.entity';
import { User } from '../users/entities/user.entity';
import { VideoComment } from '../video-comment/entities/video-comment.entity';
import { VideoInteraction } from '../video-interaction/entities/video-interaction.entity';
import { VideoReport } from '../video-report/entities/video-report.entity';
import { Video } from '../video/entities/video.entity';
import { Category } from '../category/entities/category.entity';

export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  host: process.env.POSTGRES_HOST || 'localhost',
  port: parseInt(process.env.POSTGRES_PORT) || 5432,
  username: process.env.POSTGRES_USER || 'postgres',
  password: process.env.POSTGRES_PASSWORD || 'postgres',
  database: process.env.POSTGRES_DB || 'clinic_hub_db',
  migrationsRun: true,
  migrations: ['src/database/migrations/*.ts'],
  migrationsTableName: 'migrations',
  entities: [
    User,
    Video,
    Manual,
    Section,
    Subsection,
    Block,
    VideoComment,
    VideoInteraction,
    VideoReport,
    VideoBookmark,
    Category,
  ],
};

export const connectionSource = new DataSource(dataSourceOptions);
