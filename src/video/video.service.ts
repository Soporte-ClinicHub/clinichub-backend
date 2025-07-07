import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { v4 as uuid } from 'uuid';
import { CreateVideoDto } from './dto/create-video.dto';
import { UpdateVideoDto } from './dto/update-video.dto';
import { Video } from './entities/video.entity';
import { VideoStorageService } from './video-storage.service';
import { Category } from '../category/entities/category.entity'; // Assuming Category is imported from the correct path


@Injectable()
export class VideoService {
  constructor(
    @InjectRepository(Video)
    private readonly videoRepository: Repository<Video>,
    private readonly videoStorageService: VideoStorageService,
    @InjectRepository(Category)
    private readonly categoryRepository: Repository<Category>, // Assuming Category is imported from the correct path
  ) {}

  async upload(
    file: Express.Multer.File,
    createVideoDto: CreateVideoDto,
  ): Promise<Video> {
    const fileKey = `videos/${uuid()}-${file.originalname}`;
    let fileUrl: string;
    const startTime = Date.now();
    try {
      if (file.size > 5 * 1024 * 1024) {
        fileUrl = await this.videoStorageService.uploadLargeFile(fileKey, file);
      } else {
        fileUrl = await this.videoStorageService.uploadFile(fileKey, file);
      }

      let category: Category = null;
      if (createVideoDto.categoryId) {
        category = await this.categoryRepository.findOne({ where: { id: createVideoDto.categoryId } });
      } else if (createVideoDto.newCategory) {
        category = await this.categoryRepository.findOne({ where: { name: createVideoDto.newCategory } });
        if (!category) {
          category = this.categoryRepository.create({ name: createVideoDto.newCategory });
          category = await this.categoryRepository.save(category);
        }
      }

      const uploadTime = (Date.now() - startTime) / 1000;

      const video = this.videoRepository.create({
        ...createVideoDto,
        fileKey,
        fileUrl,
        contentType: file.mimetype,
        fileSize: file.size,
        uploadDuration: Math.floor(uploadTime),
      });

      return this.videoRepository.save(video);
    } catch (error) {
      throw new InternalServerErrorException(
        'Error uploading video to storage service',
      );
    }
  }

  async getVideoStream(
    id: string,
    range?: string,
  ): Promise<{
    stream: any;
    contentLength: number;
    contentRange?: string;
    contentType: string;
    statusCode: number;
  }> {
    const video = await this.videoRepository.findOne({ where: { id } });
    if (!video) {
      throw new NotFoundException(`Video with ID ${id} not found`);
    }

    const fileSize = video.fileSize;
    let start = 0;
    let end = fileSize - 1;

    // Parse Range header if present
    if (range) {
      const ranges = range.replace(/bytes=/, '').split('-');
      start = parseInt(ranges[0], 10) || 0;
      end = parseInt(ranges[1], 10) || fileSize - 1;
    }

    const contentLength = end - start + 1;
    const contentRange = range
      ? `bytes ${start}-${end}/${fileSize}`
      : undefined;

    // Get stream from storage service
    const stream = await this.videoStorageService.getFileStream(
      video.fileKey,
      start,
      end,
    );

    return {
      stream,
      contentLength,
      contentRange,
      contentType: video.contentType,
      statusCode: range ? 206 : 200,
    };
  }

  async findAll() {
    try {
      const videos = await this.videoRepository.find({ relations: ['category'] });
      console.log(videos);
      return videos;
    } catch (error) {
      throw new InternalServerErrorException(
        'Error retrieving videos from the database',
      );
    }
  }

  async findOne(id: string) {
    const video = await this.videoRepository.findOne({ where: { id } , relations: ['category'],});
    if (!video) {
      throw new NotFoundException(`Video con ID "${id}" no encontrado`);
    }
    return video;
  }

  async update(id: string, updateVideoDto: UpdateVideoDto) {
    const video = await this.findOne(id);
    const updated = this.videoRepository.merge(video, updateVideoDto);
    return this.videoRepository.save(updated);
  }

  async remove(id: string) {
    const video = await this.findOne(id);
    await this.videoStorageService.deleteFile(video.fileKey);
    return this.videoRepository.softDelete(id);
  }
}
