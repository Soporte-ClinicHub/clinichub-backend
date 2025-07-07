import { Test, TestingModule } from '@nestjs/testing';
import { VideoReportController } from './video-report.controller';
import { VideoReportService } from './video-report.service';
import { CreateVideoReportDto } from './dto/create-video-report.dto';

describe('VideoReportController', () => {
  let controller: VideoReportController;
  let service: any;

  const mockReport: CreateVideoReportDto = {
    reason: 'Test reason',
    userId: '1',
    videoId: '1',
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
      controllers: [VideoReportController],
      providers: [{ provide: VideoReportService, useValue: service }],
    }).compile();

    controller = module.get<VideoReportController>(VideoReportController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should create report', async () => {
    service.create.mockResolvedValue(mockReport);
    const result = await controller.create(mockReport);
    expect(result).toEqual(mockReport);
  });

  it('should return all reports', async () => {
    service.findAll.mockResolvedValue([mockReport]);
    const result = await controller.findAll();
    expect(result).toEqual([mockReport]);
  });

  it('should return one report', async () => {
    service.findOne.mockResolvedValue(mockReport);
    const result = await controller.findOne('1');
    expect(result).toEqual(mockReport);
  });

  it('should update report', async () => {
    service.update.mockResolvedValue(mockReport);
    const result = await controller.update('1', { reason: 'Updated' });
    expect(result).toEqual(mockReport);
  });

  it('should remove report', async () => {
    service.remove.mockResolvedValue(undefined);
    const result = await controller.remove('1');
    expect(result).toBeUndefined();
  });
});
