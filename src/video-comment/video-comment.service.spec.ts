import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VideoCommentService } from './video-comment.service';
import { VideoComment } from './entities/video-comment.entity';
import { CreateVideoCommentDto } from './dto/create-video-comment.dto';
import { UpdateVideoCommentDto } from './dto/update-video-comment.dto';
import { UserRole } from '../common/enums/user-role.enum';

describe('VideoCommentService', () => {
  let service: VideoCommentService;
  let repository: jest.Mocked<Repository<VideoComment>>;

  const mockVideoComment: VideoComment = {
    id: '123e4567-e89b-12d3-a456-426614174000',
    user: {
      id: 'user123',
      email: 'test@example.com',
      fullName: 'Test User',
      role: UserRole.ESTUDIANTE,
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
    comment: 'This is a test comment',
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
  };

  const mockCreateVideoCommentDto: CreateVideoCommentDto = {
    userId: 'user123',
    videoId: 'video123',
    comment: 'This is a test comment',
  };

  const mockUpdateVideoCommentDto: UpdateVideoCommentDto = {
    comment: 'Updated comment',
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
        VideoCommentService,
        {
          provide: getRepositoryToken(VideoComment),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<VideoCommentService>(VideoCommentService);
    repository = module.get(getRepositoryToken(VideoComment));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a video comment successfully', async () => {
      repository.create.mockReturnValue(mockVideoComment);
      repository.save.mockResolvedValue(mockVideoComment);

      const result = await service.create(mockCreateVideoCommentDto);

      expect(repository.create).toHaveBeenCalledWith(mockCreateVideoCommentDto);
      expect(repository.save).toHaveBeenCalledWith(mockVideoComment);
      expect(result).toEqual(mockVideoComment);
    });
  });

  describe('findAll', () => {
    it('should return all video comments', async () => {
      const comments = [mockVideoComment];
      repository.find.mockResolvedValue(comments);

      const result = await service.findAll();

      expect(repository.find).toHaveBeenCalled();
      expect(result).toEqual(comments);
    });
  });

  describe('findOne', () => {
    it('should return a video comment by id', async () => {
      repository.findOne.mockResolvedValue(mockVideoComment);

      const result = await service.findOne(mockVideoComment.id);

      expect(repository.findOne).toHaveBeenCalledWith({
        where: { id: mockVideoComment.id },
      });
      expect(result).toEqual(mockVideoComment);
    });
  });

  describe('update', () => {
    it('should update a video comment successfully', async () => {
      const updateResult = { affected: 1, raw: {}, generatedMaps: [] };
      repository.update.mockResolvedValue(updateResult);

      const result = await service.update(
        mockVideoComment.id,
        mockUpdateVideoCommentDto,
      );

      expect(repository.update).toHaveBeenCalledWith(
        mockVideoComment.id,
        mockUpdateVideoCommentDto,
      );
      expect(result).toEqual(updateResult);
    });
  });

  describe('remove', () => {
    it('should remove a video comment successfully', async () => {
      const deleteResult = { affected: 1, raw: {} };
      repository.delete.mockResolvedValue(deleteResult);

      const result = await service.remove(mockVideoComment.id);

      expect(repository.delete).toHaveBeenCalledWith(mockVideoComment.id);
      expect(result).toEqual(deleteResult);
    });
  });
});
