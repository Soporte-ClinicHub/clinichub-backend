import { Test, TestingModule } from '@nestjs/testing';
import { SubsectionService } from './subsection.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Subsection } from '../entities/subsection.entity';
import { Section } from '../entities/section.entity';

describe('SubsectionService', () => {
  let service: SubsectionService;
  let subsectionRepo: any;
  let sectionRepo: any;

  beforeEach(async () => {
    subsectionRepo = {
      create: jest.fn(),
      save: jest.fn(),
      find: jest.fn(),
    };
    sectionRepo = {
      findOneBy: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SubsectionService,
        { provide: getRepositoryToken(Subsection), useValue: subsectionRepo },
        { provide: getRepositoryToken(Section), useValue: sectionRepo },
      ],
    }).compile();

    service = module.get<SubsectionService>(SubsectionService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should create subsection if section exists', async () => {
    sectionRepo.findOneBy.mockResolvedValue({ id: 'sec1' });
    subsectionRepo.create.mockReturnValue({ title: 'Sub' });
    subsectionRepo.save.mockResolvedValue({ id: 'sub1', title: 'Sub' });
    const dto = { sectionId: 'sec1', title: 'Sub' };
    const result = await service.createSubsection(dto as any);
    expect(result).toEqual({ id: 'sub1', title: 'Sub' });
  });

  it('should throw if section not found', async () => {
    sectionRepo.findOneBy.mockResolvedValue(null);
    await expect(
      service.createSubsection({ sectionId: 'sec1', title: 'Sub' } as any),
    ).rejects.toThrow();
  });

  it('should reorder subsections', async () => {
    subsectionRepo.find.mockResolvedValue([
      { id: 's1', order: 1 },
      { id: 's2', order: 2 },
    ]);
    subsectionRepo.save.mockResolvedValue(undefined);
    subsectionRepo.find.mockResolvedValueOnce([
      { id: 's1', order: 1 },
      { id: 's2', order: 2 },
    ]);
    subsectionRepo.find.mockResolvedValueOnce([
      { id: 's1', order: 2 },
      { id: 's2', order: 1 },
    ]);
    const dto = {
      sectionId: 'sec1',
      subsections: [
        { id: 's1', order: 2 },
        { id: 's2', order: 1 },
      ],
    };
    const result = await service.reorderSubsections(dto as any);
    expect(Array.isArray(result)).toBe(true);
  });
});
