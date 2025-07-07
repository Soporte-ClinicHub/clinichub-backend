import { Test, TestingModule } from '@nestjs/testing';
import { ManualService } from './manual.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Manual } from '../entities/manual.entity';

describe('ManualService', () => {
  let service: ManualService;
  let manualRepo: any;

  beforeEach(async () => {
    manualRepo = {
      create: jest.fn(),
      save: jest.fn(),
      find: jest.fn(),
      findOne: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ManualService,
        { provide: getRepositoryToken(Manual), useValue: manualRepo },
      ],
    }).compile();

    service = module.get<ManualService>(ManualService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should create manual', async () => {
    manualRepo.create.mockReturnValue({ title: 'Manual' });
    manualRepo.save.mockResolvedValue({ id: '1', title: 'Manual' });
    const result = await service.createManual({ title: 'Manual' });
    expect(result).toEqual({ id: '1', title: 'Manual' });
  });

  it('should get all manuals', async () => {
    manualRepo.find.mockResolvedValue([{ id: '1' }]);
    const result = await service.getAllManuals();
    expect(result).toEqual([{ id: '1' }]);
  });

  it('should find one manual', async () => {
    manualRepo.findOne.mockResolvedValue({ id: '1' });
    const result = await service.findOneManual('1');
    expect(result).toEqual({ id: '1' });
  });

  it('should create full manual', async () => {
    manualRepo.create.mockReturnValue({ title: 'Manual', sections: [] });
    manualRepo.save.mockResolvedValue({ id: '1', title: 'Manual' });
    const dto = {
      title: 'Manual',
      sections: [
        {
          title: 'Sec',
          order: 1,
          subsections: [
            {
              title: 'Sub',
              order: 1,
              blocks: [{ type: 'TEXT', content: 'c', order: 1 }],
            },
          ],
        },
      ],
    };
    const result = await service.createFullManual(dto as any);
    expect(result).toEqual({ id: '1', title: 'Manual' });
  });
});
