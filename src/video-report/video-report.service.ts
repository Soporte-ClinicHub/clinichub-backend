import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateVideoReportDto } from './dto/create-video-report.dto';
import { VideoReport } from './entities/video-report.entity';

@Injectable()
export class VideoReportService {
  constructor(
    @InjectRepository(VideoReport)
    private readonly reportRepository: Repository<VideoReport>,
  ) {}

  create(createDto: CreateVideoReportDto) {
    const report = this.reportRepository.create({
      ...createDto,
      user: { id: createDto.userId },
      video: { id: createDto.videoId },
    });
    return this.reportRepository.save(report);
  }

  findAll() {
    return this.reportRepository.find({ relations: ['user', 'video'] });
  }

  findOne(id: string) {
    return this.reportRepository.findOne({
      where: { id },
      relations: ['user', 'video'],
    });
  }

  update(id: string, updateDto: Partial<CreateVideoReportDto>) {
    return this.reportRepository.update(id, updateDto);
  }

  remove(id: string) {
    return this.reportRepository.delete(id);
  }
}
