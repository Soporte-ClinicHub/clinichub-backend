import { Test, TestingModule } from '@nestjs/testing';
import { UserRole } from '../common/enums/user-role.enum';
import { CreateVideoBookmarkDto } from './dto/create-video-bookmark.dto';
import { VideoBookmark } from './entities/video-bookmark.entity';
import { BookmarkType } from './enum/bookmark-type.enum';
import { VideoBookmarkController } from './video-bookmark.controller';
import { VideoBookmarkService } from './video-bookmark.service';

describe('VideoBookmarkController', () => {
  let controller: VideoBookmarkController;
  let service: any;

  const mockCreateBookmark: CreateVideoBookmarkDto = {
    videoId: 'video-123',
    userId: 'user-123',
    note: 'Test bookmark',
    bookmarkType: BookmarkType.CUSTOM,
    position: 120,
  };

  const mockBookmark: VideoBookmark = {
    id: '1',
    deletedAt: null,
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
    user: {
      id: 'user1',
      fullName: 'Test User',
      email: 'correo@correo.com',
      role: UserRole.ESTUDIANTE,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
    note: 'Test bookmark',
    bookmarkType: BookmarkType.CUSTOM,
    position: 120,
    createdAt: new Date(),
    updatedAt: new Date(),
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
      controllers: [VideoBookmarkController],
      providers: [{ provide: VideoBookmarkService, useValue: service }],
    }).compile();

    controller = module.get<VideoBookmarkController>(VideoBookmarkController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should create bookmark', async () => {
    service.create.mockResolvedValue(mockCreateBookmark);
    const result = await controller.create(mockCreateBookmark);
    expect(result).toEqual(mockBookmark);
  });

  it('should return all bookmarks', async () => {
    service.findAll.mockResolvedValue([mockBookmark]);
    const result = await controller.findAll();
    expect(result).toEqual([mockBookmark]);
  });

  it('should return one bookmark', async () => {
    service.findOne.mockResolvedValue(mockBookmark);
    const result = await controller.findOne('1');
    expect(result).toEqual(mockBookmark);
  });

  it('should update bookmark', async () => {
    service.update.mockResolvedValue(mockBookmark);
    const result = await controller.update('1', { note: 'Updated' });
    expect(result).toEqual(mockBookmark);
  });

  it('should remove bookmark', async () => {
    service.remove.mockResolvedValue(undefined);
    const result = await controller.remove('1');
    expect(result).toBeUndefined();
  });
});
