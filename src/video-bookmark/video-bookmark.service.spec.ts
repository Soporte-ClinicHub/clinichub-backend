import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VideoBookmarkService } from './video-bookmark.service';
import { VideoBookmark } from './entities/video-bookmark.entity';
import { CreateVideoBookmarkDto } from './dto/create-video-bookmark.dto';
import { UpdateVideoBookmarkDto } from './dto/update-video-bookmark.dto';
import { UserRole } from '../common/enums/user-role.enum';
import { BookmarkType } from './enum/bookmark-type.enum';

describe('VideoBookmarkService', () => {
  let service: VideoBookmarkService;
  let repository: jest.Mocked<Repository<VideoBookmark>>;

  const mockVideoBookmark: VideoBookmark = {
    id: '123e4567-e89b-12d3-a456-426614174000',
    bookmarkType: BookmarkType.CUSTOM,
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
    position: 120,
    note: 'Important moment',
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
  };

  const mockCreateVideoBookmarkDto: CreateVideoBookmarkDto = {
    userId: 'user123',
    videoId: 'video123',
    position: 120,
    bookmarkType: BookmarkType.CUSTOM,
    note: 'Important moment',
  };

  const mockUpdateVideoBookmarkDto: UpdateVideoBookmarkDto = {
    position: 150,
    note: 'Updated note',
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
        VideoBookmarkService,
        {
          provide: getRepositoryToken(VideoBookmark),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<VideoBookmarkService>(VideoBookmarkService);
    repository = module.get(getRepositoryToken(VideoBookmark));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a video bookmark successfully', async () => {
      repository.create.mockReturnValue(mockVideoBookmark);
      repository.save.mockResolvedValue(mockVideoBookmark);

      const result = await service.create(mockCreateVideoBookmarkDto);

      expect(repository.create).toHaveBeenCalledWith(
        mockCreateVideoBookmarkDto,
      );
      expect(repository.save).toHaveBeenCalledWith(mockVideoBookmark);
      expect(result).toEqual(mockVideoBookmark);
    });
  });

  describe('findAll', () => {
    it('should return all video bookmarks', async () => {
      const bookmarks = [mockVideoBookmark];
      repository.find.mockResolvedValue(bookmarks);

      const result = await service.findAll();

      expect(repository.find).toHaveBeenCalled();
      expect(result).toEqual(bookmarks);
    });
  });

  describe('findOne', () => {
    it('should return a video bookmark by id', async () => {
      repository.findOne.mockResolvedValue(mockVideoBookmark);

      const result = await service.findOne(mockVideoBookmark.id);

      expect(repository.findOne).toHaveBeenCalledWith({
        where: { id: mockVideoBookmark.id },
      });
      expect(result).toEqual(mockVideoBookmark);
    });
  });

  describe('update', () => {
    it('should update a video bookmark successfully', async () => {
      const updateResult = { affected: 1, raw: {}, generatedMaps: [] };
      repository.update.mockResolvedValue(updateResult);

      const result = await service.update(
        mockVideoBookmark.id,
        mockUpdateVideoBookmarkDto,
      );

      expect(repository.update).toHaveBeenCalledWith(mockVideoBookmark.id, {
        position: mockUpdateVideoBookmarkDto.position,
        note: mockUpdateVideoBookmarkDto.note,
      });
      expect(result).toEqual(updateResult);
    });
  });

  describe('remove', () => {
    it('should remove a video bookmark successfully', async () => {
      const deleteResult = { affected: 1, raw: {} };
      repository.delete.mockResolvedValue(deleteResult);

      const result = await service.remove(mockVideoBookmark.id);

      expect(repository.delete).toHaveBeenCalledWith(mockVideoBookmark.id);
      expect(result).toEqual(deleteResult);
    });
  });

  describe('findAllByUser', () => {
    it('should return all bookmarks for a user', async () => {
      const bookmarks = [mockVideoBookmark];
      repository.find.mockResolvedValue(bookmarks);

      const result = await service.findAllByUser('user123');

      expect(repository.find).toHaveBeenCalledWith({
        where: { user: { id: 'user123' } },
      });
      expect(result).toEqual(bookmarks);
    });
  });

  describe('findAllByUserAndVideo', () => {
    it('should return all bookmarks for a user and video', async () => {
      const bookmarks = [mockVideoBookmark];
      repository.find.mockResolvedValue(bookmarks);

      const result = await service.findAllByUserAndVideo('user123', 'video123');

      expect(repository.find).toHaveBeenCalledWith({
        where: { user: { id: 'user123' }, video: { id: 'video123' } },
      });
      expect(result).toEqual(bookmarks);
    });
  });
});
