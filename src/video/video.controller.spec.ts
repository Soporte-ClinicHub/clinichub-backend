import { Test, TestingModule } from '@nestjs/testing';
import { VideoController } from './video.controller';
import { VideoService } from './video.service';

describe('VideoController', () => {
  let controller: VideoController;
  let service: any;

  const mockVideo = { id: '1', title: 'Test', description: 'Desc' };

  beforeEach(async () => {
    service = {
      upload: jest.fn(),
      findAll: jest.fn(),
      findOne: jest.fn(),
      getVideoStream: jest.fn(),
      update: jest.fn(),
      remove: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      controllers: [VideoController],
      providers: [{ provide: VideoService, useValue: service }],
    }).compile();

    controller = module.get<VideoController>(VideoController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should upload video', async () => {
    service.upload.mockResolvedValue(mockVideo);
    const result = await controller.uploadVideo({} as any, {
      title: 'Test',
      description: 'Desc',
    });
    expect(result.data).toEqual(mockVideo);
    expect(result.statusCode).toBe(201);
  });

  it('should return all videos', async () => {
    service.findAll.mockResolvedValue([mockVideo]);
    const result = await controller.findAll();
    expect(result.data).toEqual([mockVideo]);
  });

  it('should return one video', async () => {
    service.findOne.mockResolvedValue(mockVideo);
    const result = await controller.findOne('1');
    expect(result.data).toEqual(mockVideo);
  });

  it('should update video', async () => {
    service.update.mockResolvedValue(mockVideo);
    const result = await controller.update('1', { title: 'Test' });
    expect(result.data).toEqual(mockVideo);
    expect(result.message).toBeDefined();
  });

  it('should remove video', async () => {
    service.remove.mockResolvedValue(undefined);
    const result = await controller.remove('1');
    expect(result.statusCode).toBe(200);
    expect(result.message).toBeDefined();
  });
});
