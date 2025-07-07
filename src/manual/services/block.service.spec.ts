import { Test, TestingModule } from '@nestjs/testing';
import { BlockService } from './block.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Block } from '../entities/block.entity';
import { Subsection } from '../entities/subsection.entity';

describe('BlockService', () => {
  let service: BlockService;
  let blockRepo: any;
  let subsectionRepo: any;

  beforeEach(async () => {
    blockRepo = {
      create: jest.fn(),
      save: jest.fn(),
      find: jest.fn(),
    };
    subsectionRepo = {
      findOneBy: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BlockService,
        { provide: getRepositoryToken(Block), useValue: blockRepo },
        { provide: getRepositoryToken(Subsection), useValue: subsectionRepo },
      ],
    }).compile();

    service = module.get<BlockService>(BlockService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should create block if subsection exists', async () => {
    subsectionRepo.findOneBy.mockResolvedValue({ id: 'sub1' });
    blockRepo.create.mockReturnValue({ id: 'block1' });
    blockRepo.save.mockResolvedValue({ id: 'block1' });
    const dto = {
      subsectionId: 'sub1',
      type: 'TEXT',
      content: 'abc',
      order: 1,
    };
    const result = await service.createBlock(dto as any);
    expect(result).toEqual({ id: 'block1' });
  });

  it('should throw if subsection not found', async () => {
    subsectionRepo.findOneBy.mockResolvedValue(null);
    await expect(
      service.createBlock({ subsectionId: 'sub1' } as any),
    ).rejects.toThrow();
  });

  it('should reorder blocks', async () => {
    blockRepo.find.mockResolvedValue([
      { id: 'b1', order: 1 },
      { id: 'b2', order: 2 },
    ]);
    blockRepo.save.mockResolvedValue(undefined);
    blockRepo.find.mockResolvedValueOnce([
      { id: 'b1', order: 1 },
      { id: 'b2', order: 2 },
    ]);
    blockRepo.find.mockResolvedValueOnce([
      { id: 'b1', order: 2 },
      { id: 'b2', order: 1 },
    ]);
    const dto = {
      subsectionId: 'sub1',
      blocks: [
        { id: 'b1', order: 2 },
        { id: 'b2', order: 1 },
      ],
    };
    const result = await service.reorderBlocks(dto as any);
    expect(Array.isArray(result)).toBe(true);
  });
});
