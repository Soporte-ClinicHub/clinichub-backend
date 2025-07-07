import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { VideoInteractionService } from './video-interaction.service';
import { VideoInteraction } from './entities/video-interaction.entity';
import { CreateVideoInteractionDto } from './dto/create-video-interaction.dto';
import { UpdateVideoInteractionDto } from './dto/update-video-interaction.dto';
import { UserRole } from '../common/enums/user-role.enum';
import { VideoInteractionType } from './enum/video-interaction.enums';

describe('VideoInteractionService', () => {
  let service: VideoInteractionService;
  let repository: jest.Mocked<Repository<VideoInteraction>>;

  const mockVideoInteraction: VideoInteraction = {
    id: '123e4567-e89b-12d3-a456-426614174000',
    type: VideoInteractionType.LIKE,
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
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
  };

  const mockCreateVideoInteractionDto: CreateVideoInteractionDto = {
    userId: 'user123',
    videoId: 'video123',
    type: VideoInteractionType.LIKE,
  };

  const mockUpdateVideoInteractionDto: UpdateVideoInteractionDto = {
    type: VideoInteractionType.DISLIKE,
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
        VideoInteractionService,
        {
          provide: getRepositoryToken(VideoInteraction),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<VideoInteractionService>(VideoInteractionService);
    repository = module.get(getRepositoryToken(VideoInteraction));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a video interaction successfully', async () => {
      repository.create.mockReturnValue(mockVideoInteraction);
      repository.save.mockResolvedValue(mockVideoInteraction);

      const result = await service.create(mockCreateVideoInteractionDto);

      expect(repository.create).toHaveBeenCalledWith({
        type: mockCreateVideoInteractionDto.type,
        user: { id: mockCreateVideoInteractionDto.userId },
        video: { id: mockCreateVideoInteractionDto.videoId },
      });
      expect(repository.save).toHaveBeenCalledWith(mockVideoInteraction);
      expect(result).toEqual(mockVideoInteraction);
    });

    it('should throw InternalServerErrorException when creation fails', async () => {
      repository.create.mockImplementation(() => {
        throw new Error('Database error');
      });

      await expect(
        service.create(mockCreateVideoInteractionDto),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('findAll', () => {
    it('should return all video interactions', async () => {
      const interactions = [mockVideoInteraction];
      repository.find.mockResolvedValue(interactions);

      const result = await service.findAll();

      expect(repository.find).toHaveBeenCalled();
      expect(result).toEqual(interactions);
    });

    it('should throw InternalServerErrorException when find fails', async () => {
      repository.find.mockRejectedValue(new Error('Database error'));

      await expect(service.findAll()).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('findOne', () => {
    it('should return a video interaction by id', async () => {
      repository.findOne.mockResolvedValue(mockVideoInteraction);

      const result = await service.findOne(mockVideoInteraction.id);

      expect(repository.findOne).toHaveBeenCalledWith({
        where: { id: mockVideoInteraction.id },
      });
      expect(result).toEqual(mockVideoInteraction);
    });

    it('should throw NotFoundException when interaction not found', async () => {
      repository.findOne.mockResolvedValue(null);

      await expect(service.findOne('non-existent-id')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw InternalServerErrorException when findOne fails', async () => {
      repository.findOne.mockRejectedValue(new Error('Database error'));

      await expect(service.findOne(mockVideoInteraction.id)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('update', () => {
    it('should update a video interaction successfully', async () => {
      const updateResult = { affected: 1, raw: {}, generatedMaps: [] };
      repository.update.mockResolvedValue(updateResult);

      const result = await service.update(
        mockVideoInteraction.id,
        mockUpdateVideoInteractionDto,
      );

      expect(repository.update).toHaveBeenCalledWith(
        mockVideoInteraction.id,
        mockUpdateVideoInteractionDto,
      );
      expect(result).toEqual(updateResult);
    });

    it('should throw InternalServerErrorException when update fails', async () => {
      repository.update.mockRejectedValue(new Error('Database error'));

      await expect(
        service.update(mockVideoInteraction.id, mockUpdateVideoInteractionDto),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('remove', () => {
    it('should remove a video interaction successfully', async () => {
      const deleteResult = { affected: 1, raw: {} };
      repository.delete.mockResolvedValue(deleteResult);

      const result = await service.remove(mockVideoInteraction.id);

      expect(repository.delete).toHaveBeenCalledWith(mockVideoInteraction.id);
      expect(result).toEqual(deleteResult);
    });

    it('should throw InternalServerErrorException when delete fails', async () => {
      repository.delete.mockRejectedValue(new Error('Database error'));

      await expect(service.remove(mockVideoInteraction.id)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });
});
