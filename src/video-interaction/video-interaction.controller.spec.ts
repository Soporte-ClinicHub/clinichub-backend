import { Test, TestingModule } from '@nestjs/testing';
import { VideoInteractionController } from './video-interaction.controller';
import { VideoInteractionService } from './video-interaction.service';
import { CreateVideoInteractionDto } from './dto/create-video-interaction.dto';
import { VideoInteractionType } from './enum/video-interaction.enums';
import { VideoInteraction } from './entities/video-interaction.entity';
import { UserRole } from '../common/enums/user-role.enum';
import { UpdateVideoInteractionDto } from './dto/update-video-interaction.dto';

describe('VideoInteractionController', () => {
  let controller: VideoInteractionController;
  let service: any;

  const mockCreateInteractionDto: CreateVideoInteractionDto = {
    type: VideoInteractionType.LIKE,
    userId: 'user1',
    videoId: 'video1',
  };

  const mockUpdateInteractionDto: UpdateVideoInteractionDto = {
    type: VideoInteractionType.DISLIKE,
  };

  const mockInteraction: VideoInteraction = {
    id: '1',
    type: VideoInteractionType.LIKE,
    user: {
      id: 'user1',
      fullName: 'Test User',
      email: 'correo@correo.com',
      role: UserRole.ESTUDIANTE,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
    video: {
      id: 'video1',
      title: 'Test Video',
      description: 'This is a test video',
      fileUrl: 'http://example.com/video1',
      contentType: 'video/mp4',
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      fileKey: 'video1.mp4',
      fileSize: 1024,
      uploadDuration: 60,
      category: { id: 'cat1', name: 'Test Category', videos: [] },
    },
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
  };

  beforeEach(async () => {
    service = {
      create: jest.fn(),
      findAll: jest.fn(),
      findOne: jest.fn(),
      update: jest.fn(),
      remove: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      controllers: [VideoInteractionController],
      providers: [{ provide: VideoInteractionService, useValue: service }],
    }).compile();

    controller = module.get<VideoInteractionController>(
      VideoInteractionController,
    );
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should create interaction', async () => {
    service.create.mockResolvedValue(mockInteraction);
    const result = await controller.create(mockCreateInteractionDto);
    expect(result.data).toEqual(mockInteraction);
    expect(result.statusCode).toBe(201);
  });

  it('should return all interactions', async () => {
    service.findAll.mockResolvedValue([mockInteraction]);
    const result = await controller.findAll();
    expect(result.data).toEqual([mockInteraction]);
    expect(result.statusCode).toBe(200);
  });

  it('should return one interaction', async () => {
    service.findOne.mockResolvedValue(mockInteraction);
    const result = await controller.findOne('1');
    expect(result.data).toEqual(mockInteraction);
    expect(result.statusCode).toBe(200);
  });

  it('should update interaction', async () => {
    service.update.mockResolvedValue(mockInteraction);
    const result = await controller.update('1', mockUpdateInteractionDto);
    expect(result.data).toEqual(mockInteraction);
    expect(result.statusCode).toBe(200);
  });

  it('should remove interaction', async () => {
    service.remove.mockResolvedValue(undefined);
    const result = await controller.remove('1');
    expect(result.statusCode).toBe(200);
  });
});
