.import { Test, TestingModule } from '@nestjs/testing';
import { SectionService } from './section.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Section } from '../entities/section.entity';
import { Manual } from '../entities/manual.entity';

describe('SectionService', () => {
  let service: SectionService;
  let sectionRepo: any;
  let manualRepo: any;

  beforeEach(async () => {
    sectionRepo = {
      create: jest.fn(),
      save: jest.fn(),
      find: jest.fn(),
      findOneBy: jest.fn(),
    };
    manualRepo = {
      findOneBy: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SectionService,
        { provide: getRepositoryToken(Section), useValue: sectionRepo },
        { provide: getRepositoryToken(Manual), useValue: manualRepo },
      ],
    }).compile();

    service = module.get<SectionService>(SectionService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should create section if manual exists', async () => {
    manualRepo.findOneBy.mockResolvedValue({ id: 'm1' });
    sectionRepo.create.mockReturnValue({ title: 'Sec' });
    sectionRepo.save.mockResolvedValue({ id: 's1', title: 'Sec' });
    const dto = { manualId: 'm1', title: 'Sec' };
    const result = await service.createSection(dto as any);
    expect(result).toEqual({ id: 's1', title: 'Sec' });
  });

  it('should throw if manual not found', async () => {
    manualRepo.findOneBy.mockResolvedValue(null);
    await expect(
      service.createSection({ manualId: 'm1', title: 'Sec' } as any),
    ).rejects.toThrow();
  });

  it('should reorder sections', async () => {
    sectionRepo.find.mockResolvedValue([
      { id: 's1', order: 1 },
      { id: 's2', order: 2 },
    ]);
    sectionRepo.save.mockResolvedValue(undefined);
    sectionRepo.find.mockResolvedValueOnce([
      { id: 's1', order: 1 },
      { id: 's2', order: 2 },
    ]);
    sectionRepo.find.mockResolvedValueOnce([
      { id: 's1', order: 2 },
      { id: 's2', order: 1 },
    ]);
    const dto = {
      manualId: 'm1',
      sections: [
        { id: 's1', order: 2 },
        { id: 's2', order: 1 },
      ],
    };
    const result = await service.reorderSections(dto as any);
    expect(Array.isArray(result)).toBe(true);
  });
});
