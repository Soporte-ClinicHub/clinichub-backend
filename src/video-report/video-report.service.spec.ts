import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VideoReportService } from './video-report.service';
import { VideoReport } from './entities/video-report.entity';
import { CreateVideoReportDto } from './dto/create-video-report.dto';
import { VideoReportStatus } from './enum/video-report-status.enum';

describe('VideoReportService', () => {
  let service: VideoReportService;
  let repository: jest.Mocked<Repository<VideoReport>>;

  const mockVideoReport: VideoReport = {
    id: '123e4567-e89b-12d3-a456-426614174000',
    user: {
      id: 'user123',
      email: 'test@example.com',
      fullName: 'Test User',
      role: 'USER' as any,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
    video: {
      id: 'video123',
      title: 'Test Video',
      description: 'Test Description',
      fileKey: 'videos/test-key',
      fileUrl: 'https://bucket.s3.amazonaws.com/videos/test-key',
      contentType: 'video/mp4',
      fileSize: 1024000,
      uploadDuration: 5,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
    reason: 'Contenido inapropiado',
    status: VideoReportStatus.PENDING,
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
  };

  const mockCreateVideoReportDto: CreateVideoReportDto = {
    userId: 'user123',
    videoId: 'video123',
    reason: 'Contenido inapropiado',
  };

  beforeEach(async () => {
    const mockRepository = {
      create: jest.fn(),
      save: jest.fn(),
      find: jest.fn(),
      findOne: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VideoReportService,
        {
          provide: getRepositoryToken(VideoReport),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<VideoReportService>(VideoReportService);
    repository = module.get(getRepositoryToken(VideoReport));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a video report successfully', async () => {
      repository.create.mockReturnValue(mockVideoReport);
      repository.save.mockResolvedValue(mockVideoReport);

      const result = await service.create(mockCreateVideoReportDto);

      expect(repository.create).toHaveBeenCalledWith({
        ...mockCreateVideoReportDto,
        user: { id: mockCreateVideoReportDto.userId },
        video: { id: mockCreateVideoReportDto.videoId },
      });
      expect(repository.save).toHaveBeenCalledWith(mockVideoReport);
      expect(result).toEqual(mockVideoReport);
    });
  });

  describe('findAll', () => {
    it('should return all video reports with relations', async () => {
      const reports = [mockVideoReport];
      repository.find.mockResolvedValue(reports);

      const result = await service.findAll();

      expect(repository.find).toHaveBeenCalledWith({
        relations: ['user', 'video'],
      });
      expect(result).toEqual(reports);
    });
  });

  describe('findOne', () => {
    it('should return a video report by id with relations', async () => {
      repository.findOne.mockResolvedValue(mockVideoReport);

      const result = await service.findOne(mockVideoReport.id);

      expect(repository.findOne).toHaveBeenCalledWith({
        where: { id: mockVideoReport.id },
        relations: ['user', 'video'],
      });
      expect(result).toEqual(mockVideoReport);
    });
  });

  describe('update', () => {
    it('should update a video report successfully', async () => {
      const updateResult = { affected: 1, raw: {}, generatedMaps: [] };
      const updateDto = { reason: 'Updated reason' };
      repository.update.mockResolvedValue(updateResult);

      const result = await service.update(mockVideoReport.id, updateDto);

      expect(repository.update).toHaveBeenCalledWith(
        mockVideoReport.id,
        updateDto,
      );
      expect(result).toEqual(updateResult);
    });
  });

  describe('remove', () => {
    it('should remove a video report successfully', async () => {
      const deleteResult = { affected: 1, raw: {} };
      repository.delete.mockResolvedValue(deleteResult);

      const result = await service.remove(mockVideoReport.id);

      expect(repository.delete).toHaveBeenCalledWith(mockVideoReport.id);
      expect(result).toEqual(deleteResult);
    });
  });
});
