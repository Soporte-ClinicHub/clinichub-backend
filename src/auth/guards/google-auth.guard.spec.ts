import { GoogleAuthGuard } from './google-auth.guard';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { OAuth2Client } from 'google-auth-library';

jest.mock('google-auth-library', () => {
  return {
    OAuth2Client: jest.fn().mockImplementation(() => ({
      verifyIdToken: jest.fn(),
    })),
  };
});

describe('GoogleAuthGuard', () => {
  let guard: GoogleAuthGuard;
  let mockOAuth2Client: any;

  beforeEach(() => {
    process.env.GOOGLE_CLIENT_ID = 'test-client-id';
    guard = new GoogleAuthGuard();
    mockOAuth2Client = (guard as any).client;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  it('should allow valid token and institutional email', async () => {
    const mockPayload = { email: 'test@alumnos.ucn.cl', name: 'Test User' };
    mockOAuth2Client.verifyIdToken.mockResolvedValue({
      getPayload: () => mockPayload,
    });
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { authorization: 'Bearer validtoken' },
        }),
      }),
    };
    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('should throw UnauthorizedException if no token', async () => {
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { authorization: '' },
        }),
      }),
    };
    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('should throw ForbiddenException if email is not institutional', async () => {
    mockOAuth2Client.verifyIdToken.mockResolvedValue({
      getPayload: () => ({ email: 'notucn@gmail.com' }),
    });
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { authorization: 'Bearer validtoken' },
        }),
      }),
    };
    await expect(guard.canActivate(context)).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('should throw UnauthorizedException on verifyIdToken error', async () => {
    mockOAuth2Client.verifyIdToken.mockRejectedValue(new Error('fail'));
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { authorization: 'Bearer sometoken' },
        }),
      }),
    };
    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });
});
