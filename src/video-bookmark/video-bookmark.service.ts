import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateVideoBookmarkDto } from './dto/create-video-bookmark.dto';
import { UpdateVideoBookmarkDto } from './dto/update-video-bookmark.dto';
import { VideoBookmark } from './entities/video-bookmark.entity';

@Injectable()
export class VideoBookmarkService {
  constructor(
    @InjectRepository(VideoBookmark)
    private readonly bookmarkRepository: Repository<VideoBookmark>,
  ) {}

  create(dto: CreateVideoBookmarkDto) {
    const bookmark = this.bookmarkRepository.create(dto);
    return this.bookmarkRepository.save(bookmark);
  }

  findAll() {
    return this.bookmarkRepository.find();
  }

  findOne(id: string) {
    return this.bookmarkRepository.findOne({ where: { id } });
  }

  update(id: string, dto: UpdateVideoBookmarkDto) {
    // Solo actualiza campos simples, no relaciones
    const { position, note } = dto;
    return this.bookmarkRepository.update(id, { position, note });
  }

  remove(id: string) {
    return this.bookmarkRepository.delete(id);
  }

  findAllByUser(userId: string) {
    return this.bookmarkRepository.find({ where: { user: { id: userId } } });
  }

  findAllByUserAndVideo(userId: string, videoId: string) {
    return this.bookmarkRepository.find({
      where: { user: { id: userId }, video: { id: videoId } },
    });
  }
}
