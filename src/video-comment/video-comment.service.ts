import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VideoComment } from './entities/video-comment.entity';
import { CreateVideoCommentDto } from './dto/create-video-comment.dto';
import { UpdateVideoCommentDto } from './dto/update-video-comment.dto';

@Injectable()
export class VideoCommentService {
  constructor(
    @InjectRepository(VideoComment)
    private readonly commentRepository: Repository<VideoComment>,
  ) {}

  async create(dto: CreateVideoCommentDto) {
    const comment = this.commentRepository.create({
      userId: dto.userId,
      videoId: dto.videoId,
      comment: dto.comment,
    });
    
    const savedComment = await this.commentRepository.save(comment);
    
    // Buscar el comentario con las relaciones incluidas
    return this.commentRepository.findOne({
      where: { id: savedComment.id },
      relations: ['user'],
    });
  }

  findAll() {
    return this.commentRepository.find({
      relations: ['user'],
      order: { createdAt: 'DESC' },
    });
  }

  findOne(id: string) {
    return this.commentRepository.findOne({ 
      where: { id },
      relations: ['user'],
    });
  }

  // Agregar método para buscar por videoId
  findByVideoId(videoId: string) {
    return this.commentRepository.find({
      where: { videoId },
      relations: ['user'],
      order: { createdAt: 'DESC' },
    });
  }

  async update(id: string, dto: UpdateVideoCommentDto) {
    await this.commentRepository.update(id, dto);
    return this.findOne(id);
  }

  remove(id: string) {
    return this.commentRepository.softDelete(id);
  }
}