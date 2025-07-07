import { FirebaseAuthGuard } from './firebase-auth.guard';
import {
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';

describe('FirebaseAuthGuard', () => {
  let guard: FirebaseAuthGuard;
  let firebaseService: any;

  beforeEach(() => {
    firebaseService = {
      verifyIdToken: jest.fn(),
    };
    guard = new FirebaseAuthGuard(firebaseService);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  it('should allow valid token and institutional email', async () => {
    const mockDecoded = { email: 'test@alumnos.ucn.cl' };
    firebaseService.verifyIdToken.mockResolvedValue(mockDecoded);
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { authorization: 'Bearer validtoken' },
        }),
      }),
    };
    await expect(guard.canActivate(context as ExecutionContext)).resolves.toBe(
      true,
    );
  });

  it('should throw UnauthorizedException if no token', async () => {
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { authorization: '' },
        }),
      }),
    };
    await expect(
      guard.canActivate(context as ExecutionContext),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('should throw ForbiddenException if email is not institutional', async () => {
    firebaseService.verifyIdToken.mockResolvedValue({
      email: 'notucn@gmail.com',
    });
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { authorization: 'Bearer validtoken' },
        }),
      }),
    };
    await expect(
      guard.canActivate(context as ExecutionContext),
    ).rejects.toThrow(ForbiddenException);
  });

  it('should throw UnauthorizedException on verifyIdToken error', async () => {
    firebaseService.verifyIdToken.mockRejectedValue(new Error('fail'));
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { authorization: 'Bearer sometoken' },
        }),
      }),
    };
    await expect(
      guard.canActivate(context as ExecutionContext),
    ).rejects.toThrow(UnauthorizedException);
  });
});
