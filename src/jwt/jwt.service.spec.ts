import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from './jwt.service';
import { JwtService as NestJwtService } from '@nestjs/jwt';
import config from '../config/config';

describe('JwtService', () => {
  let service: JwtService;

  beforeEach(async () => {
    const mockNestJwtService = {
      signAsync: jest.fn(),
      verifyAsync: jest.fn(),
      sign: jest.fn(),
      verify: jest.fn(),
      decode: jest.fn(),
    };

    const mockConfig = {
      jwt: {
        accessSecret: 'test-secret',
        accessExpiresIn: '15m',
        refreshSecret: 'test-refresh-secret',
        refreshExpiresIn: '7d',
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtService,
        {
          provide: NestJwtService,
          useValue: mockNestJwtService,
        },
        {
          provide: config.KEY,
          useValue: mockConfig,
        },
      ],
    }).compile();

    service = module.get<JwtService>(JwtService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
