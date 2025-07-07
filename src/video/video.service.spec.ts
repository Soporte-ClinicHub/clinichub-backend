import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { NotFoundException } from '@nestjs/common';
import { VideoService } from './video.service';
import { Video } from './entities/video.entity';
import { VideoStorageService } from './video-storage.service';
import { CreateVideoDto } from './dto/create-video.dto';
import { UpdateVideoDto } from './dto/update-video.dto';

describe('VideoService', () => {
  let service: VideoService;
  let videoRepository: jest.Mocked<Repository<Video>>;
  let videoStorageService: jest.Mocked<VideoStorageService>;

  const mockVideo: Video = {
    id: '123e4567-e89b-12d3-a456-426614174000',
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
  };

  const mockFile: Express.Multer.File = {
    fieldname: 'file',
    originalname: 'test-video.mp4',
    encoding: '7bit',
    mimetype: 'video/mp4',
    size: 1024000,
    buffer: Buffer.from('mock video data'),
    destination: '',
    filename: '',
    path: '',
    stream: null,
  };

  const mockCreateVideoDto: CreateVideoDto = {
    title: 'Test Video',
    description: 'Test Description',
  };

  const mockUpdateVideoDto: UpdateVideoDto = {
    title: 'Updated Video',
    description: 'Updated Description',
  };

  beforeEach(async () => {
    const mockRepository = {
      create: jest.fn(),
      save: jest.fn(),
      find: jest.fn(),
      findOne: jest.fn(),
      merge: jest.fn(),
      softDelete: jest.fn(),
    };

    const mockStorageService = {
      uploadFile: jest.fn(),
      uploadLargeFile: jest.fn(),
      getFile: jest.fn(),
      deleteFile: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VideoService,
        {
          provide: getRepositoryToken(Video),
          useValue: mockRepository,
        },
        {
          provide: VideoStorageService,
          useValue: mockStorageService,
        },
      ],
    }).compile();

    service = module.get<VideoService>(VideoService);
    videoRepository = module.get(getRepositoryToken(Video));
    videoStorageService = module.get(VideoStorageService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('upload', () => {
    it('should upload a small file successfully', async () => {
      const fileUrl = 'https://bucket.s3.amazonaws.com/videos/test-key';
      videoStorageService.uploadFile.mockResolvedValue(fileUrl);
      videoRepository.create.mockReturnValue(mockVideo);
      videoRepository.save.mockResolvedValue(mockVideo);

      const result = await service.upload(mockFile, mockCreateVideoDto);

      expect(videoStorageService.uploadFile).toHaveBeenCalledWith(
        expect.stringContaining('videos/'),
        mockFile,
      );
      expect(videoRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          title: mockCreateVideoDto.title,
          description: mockCreateVideoDto.description,
          contentType: mockFile.mimetype,
          fileSize: mockFile.size,
        }),
      );
      expect(videoRepository.save).toHaveBeenCalledWith(mockVideo);
      expect(result).toEqual(mockVideo);
    });

    it('should upload a large file successfully', async () => {
      const largeFile = { ...mockFile, size: 10 * 1024 * 1024 }; // 10MB
      const fileUrl = 'https://bucket.s3.amazonaws.com/videos/test-key';
      videoStorageService.uploadLargeFile.mockResolvedValue(fileUrl);
      videoRepository.create.mockReturnValue(mockVideo);
      videoRepository.save.mockResolvedValue(mockVideo);

      const result = await service.upload(largeFile, mockCreateVideoDto);

      expect(videoStorageService.uploadLargeFile).toHaveBeenCalledWith(
        expect.stringContaining('videos/'),
        largeFile,
      );
      expect(result).toEqual(mockVideo);
    });
  });

  describe('getVideoStream', () => {
    it('should return video stream successfully', async () => {
      const buffer = Buffer.from('video data');
      videoRepository.findOne.mockResolvedValue(mockVideo);
      videoStorageService.getFile.mockResolvedValue(buffer);

      const result = await service.getVideoStream(mockVideo.id);

      expect(videoRepository.findOne).toHaveBeenCalledWith({
        where: { id: mockVideo.id },
      });
      expect(videoStorageService.getFile).toHaveBeenCalledWith(
        mockVideo.fileKey,
      );
      expect(result).toEqual({
        buffer,
        contentType: mockVideo.contentType,
      });
    });

    it('should throw NotFoundException when video not found', async () => {
      videoRepository.findOne.mockResolvedValue(null);

      await expect(service.getVideoStream('non-existent-id')).rejects.toThrow(
        NotFoundException,
      );
      expect(videoRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'non-existent-id' },
      });
    });
  });

  describe('findAll', () => {
    it('should return all videos', async () => {
      const videos = [mockVideo];
      videoRepository.find.mockResolvedValue(videos);

      const result = await service.findAll();

      expect(videoRepository.find).toHaveBeenCalled();
      expect(result).toEqual(videos);
    });
  });

  describe('findOne', () => {
    it('should return a video by id', async () => {
      videoRepository.findOne.mockResolvedValue(mockVideo);

      const result = await service.findOne(mockVideo.id);

      expect(videoRepository.findOne).toHaveBeenCalledWith({
        where: { id: mockVideo.id },
      });
      expect(result).toEqual(mockVideo);
    });

    it('should throw NotFoundException when video not found', async () => {
      videoRepository.findOne.mockResolvedValue(null);

      await expect(service.findOne('non-existent-id')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('update', () => {
    it('should update a video successfully', async () => {
      const updatedVideo = { ...mockVideo, ...mockUpdateVideoDto };
      videoRepository.findOne.mockResolvedValue(mockVideo);
      videoRepository.merge.mockReturnValue(updatedVideo);
      videoRepository.save.mockResolvedValue(updatedVideo);

      const result = await service.update(mockVideo.id, mockUpdateVideoDto);

      expect(videoRepository.findOne).toHaveBeenCalledWith({
        where: { id: mockVideo.id },
      });
      expect(videoRepository.merge).toHaveBeenCalledWith(
        mockVideo,
        mockUpdateVideoDto,
      );
      expect(videoRepository.save).toHaveBeenCalledWith(updatedVideo);
      expect(result).toEqual(updatedVideo);
    });

    it('should throw NotFoundException when video not found', async () => {
      videoRepository.findOne.mockResolvedValue(null);

      await expect(
        service.update('non-existent-id', mockUpdateVideoDto),
      ).rejects.toThrow(NotFoundException);
    });
  });
  describe('remove', () => {
    it('should remove a video successfully', async () => {
      const deleteResult = {
        affected: 1,
        raw: {},
        generatedMaps: [],
      };
      videoRepository.findOne.mockResolvedValue(mockVideo);
      videoStorageService.deleteFile.mockResolvedValue(undefined);
      videoRepository.softDelete.mockResolvedValue(deleteResult);

      const result = await service.remove(mockVideo.id);

      expect(videoRepository.findOne).toHaveBeenCalledWith({
        where: { id: mockVideo.id },
      });
      expect(videoStorageService.deleteFile).toHaveBeenCalledWith(
        mockVideo.fileKey,
      );
      expect(videoRepository.softDelete).toHaveBeenCalledWith(mockVideo.id);
      expect(result).toEqual(deleteResult);
    });

    it('should throw NotFoundException when video not found', async () => {
      videoRepository.findOne.mockResolvedValue(null);

      await expect(service.remove('non-existent-id')).rejects.toThrow(
        NotFoundException,
      );
    });
  });
});
