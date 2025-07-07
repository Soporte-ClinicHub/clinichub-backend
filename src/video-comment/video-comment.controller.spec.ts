import { Test, TestingModule } from '@nestjs/testing';
import { VideoCommentController } from './video-comment.controller';
import { VideoCommentService } from './video-comment.service';
import { CreateVideoCommentDto } from './dto/create-video-comment.dto';

describe('VideoCommentController', () => {
  let controller: VideoCommentController;
  let service: any;

  const mockComment = { id: '1', comment: 'Test' };

  beforeEach(async () => {
    service = {
      create: jest.fn(),
      findAll: jest.fn(),
      findOne: jest.fn(),
      update: jest.fn(),
      remove: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      controllers: [VideoCommentController],
      providers: [{ provide: VideoCommentService, useValue: service }],
    }).compile();

    controller = module.get<VideoCommentController>(VideoCommentController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should create comment', async () => {
    service.create.mockResolvedValue(mockComment);
    const mockCommentDto: CreateVideoCommentDto = {
      comment: 'Test',
      videoId: '1',
      userId: '1',
    };
    const result = await controller.create(mockCommentDto);
    expect(result).toEqual(mockComment);
  });

  it('should return all comments', async () => {
    service.findAll.mockResolvedValue([mockComment]);
    const result = await controller.findAll();
    expect(result).toEqual([mockComment]);
  });

  it('should return one comment', async () => {
    service.findOne.mockResolvedValue(mockComment);
    const result = await controller.findOne('1');
    expect(result).toEqual(mockComment);
  });

  it('should update comment', async () => {
    service.update.mockResolvedValue(mockComment);
    const result = await controller.update('1', { comment: 'Updated' });
    expect(result).toEqual(mockComment);
  });

  it('should remove comment', async () => {
    service.remove.mockResolvedValue(undefined);
    const result = await controller.remove('1');
    expect(result).toBeUndefined();
  });
});
