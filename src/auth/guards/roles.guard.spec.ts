import { RolesGuard } from './roles.guard';
import { Reflector } from '@nestjs/core';
import { ForbiddenException } from '@nestjs/common';
import { UserRole } from '../../common/enums/user-role.enum';

describe('RolesGuard', () => {
  let guard: RolesGuard;
  let reflector: any;

  beforeEach(() => {
    reflector = { get: jest.fn() };
    guard = new RolesGuard(reflector);
  });

  it('should allow if no roles are set', () => {
    reflector.get.mockReturnValue(undefined);
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({ user: { role: UserRole.ESTUDIANTE } }),
      }),
      getHandler: () => {},
    };
    expect(guard.canActivate(context)).toBe(true);
  });

  it('should allow if user has allowed role', () => {
    reflector.get.mockReturnValue([UserRole.ESTUDIANTE]);
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({ user: { role: UserRole.ESTUDIANTE } }),
      }),
      getHandler: () => {},
    };
    expect(guard.canActivate(context)).toBe(true);
  });

  it('should throw ForbiddenException if user has not allowed role', () => {
    reflector.get.mockReturnValue([UserRole.PROFESOR]);
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({ user: { role: UserRole.ESTUDIANTE } }),
      }),
      getHandler: () => {},
    };
    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  it('should throw ForbiddenException if no user', () => {
    reflector.get.mockReturnValue([UserRole.PROFESOR]);
    const context: any = {
      switchToHttp: () => ({
        getRequest: () => ({}),
      }),
      getHandler: () => {},
    };
    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });
});
