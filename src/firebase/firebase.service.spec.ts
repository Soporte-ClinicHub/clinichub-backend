import { Test, TestingModule } from '@nestjs/testing';
import { FirebaseService } from './firebase.service';
import * as admin from 'firebase-admin';

jest.mock('firebase-admin', () => {
  const actual = jest.requireActual('firebase-admin');
  return {
    ...actual,
    apps: [],
    credential: {
      cert: jest.fn(() => ({})),
    },
    initializeApp: jest.fn(() => ({
      auth: jest.fn().mockReturnThis(),
      verifyIdToken: jest.fn(),
    })),
    app: jest.fn(() => ({
      auth: jest.fn().mockReturnThis(),
      verifyIdToken: jest.fn(),
    })),
  };
});

describe('FirebaseService', () => {
  let service: FirebaseService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        FirebaseService,
        {
          provide: 'ConfigType<typeof config>',
          useValue: {
            firebase: {
              projectId: 'pid',
              privateKey: 'key',
              clientEmail: 'email@ucn.cl',
            },
          },
        },
      ],
    }).compile();

    service = module.get<FirebaseService>(FirebaseService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should call verifyIdToken', async () => {
    const mockDecoded = { uid: 'abc', email: 'test@ucn.cl' };
    const mockAuth = {
      verifyIdToken: jest.fn().mockResolvedValue(mockDecoded),
    };
    (service as any).firebaseApp.auth = () => mockAuth;
    const result = await service.verifyIdToken('sometoken');
    expect(result).toEqual(mockDecoded);
    expect(mockAuth.verifyIdToken).toHaveBeenCalledWith('sometoken');
  });
});
