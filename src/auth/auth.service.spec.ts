import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { JwtService } from '../jwt/jwt.service';
import { UserRole } from '../common/enums/user-role.enum';
import { UnauthorizedException } from '@nestjs/common';

describe('AuthService', () => {
  let service: AuthService;
  let usersService: any;
  let jwtService: any;

  const mockUser = {
    id: 'user-id',
    email: 'test@alumnos.ucn.cl',
    fullName: 'Test User',
    role: UserRole.ESTUDIANTE,
  };

  const mockDecodedToken = {
    email: 'test@alumnos.ucn.cl',
    name: 'Test User',
    uid: 'firebase-uid',
  };

  beforeEach(async () => {
    usersService = {
      createUser: jest.fn(),
      findByEmail: jest.fn(),
      findById: jest.fn(),
    };
    jwtService = {
      generateAccessToken: jest.fn(),
      generateRefreshToken: jest.fn(),
      verifyAsync: jest.fn(),
      configService: { jwt: { refreshSecret: 'secret' } },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: usersService },
        { provide: JwtService, useValue: jwtService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('registerUser', () => {
    it('should register a user as ESTUDIANTE', async () => {
      usersService.createUser.mockResolvedValue(mockUser);
      const result = await service['registerUser'](mockDecodedToken as any);
      expect(usersService.createUser).toHaveBeenCalledWith({
        email: mockDecodedToken.email,
        fullName: mockDecodedToken.name,
        role: UserRole.ESTUDIANTE,
      });
      expect(result).toEqual(mockUser);
    });

    it('should register a user as PROFESOR if email matches', async () => {
      const profesorToken = { ...mockDecodedToken, email: 'test@ucn.cl' };
      usersService.createUser.mockResolvedValue({
        ...mockUser,
        role: UserRole.PROFESOR,
      });
      const result = await service['registerUser'](profesorToken as any);
      expect(usersService.createUser).toHaveBeenCalledWith({
        email: profesorToken.email,
        fullName: profesorToken.name,
        role: UserRole.PROFESOR,
      });
      expect(result.role).toBe(UserRole.PROFESOR);
    });
  });

  describe('loginWithFirebaseToken', () => {
    it('should login and return tokens and user', async () => {
      usersService.findByEmail.mockResolvedValue(mockUser);
      jwtService.generateAccessToken.mockResolvedValue('access-token');
      jwtService.generateRefreshToken.mockResolvedValue('refresh-token');
      const result = await service.loginWithFirebaseToken(
        mockDecodedToken as any,
      );
      expect(usersService.findByEmail).toHaveBeenCalledWith(
        mockDecodedToken.email,
      );
      expect(result).toHaveProperty('user');
      expect(result).toHaveProperty('accessToken', 'access-token');
      expect(result).toHaveProperty('refreshToken', 'refresh-token');
    });

    it('should register user if not found', async () => {
      usersService.findByEmail.mockResolvedValue(null);
      usersService.createUser.mockResolvedValue(mockUser);
      jwtService.generateAccessToken.mockResolvedValue('access-token');
      jwtService.generateRefreshToken.mockResolvedValue('refresh-token');
      const result = await service.loginWithFirebaseToken(
        mockDecodedToken as any,
      );
      expect(usersService.createUser).toHaveBeenCalled();
      expect(result.user).toEqual(mockUser);
    });

    it('should throw UnauthorizedException on error', async () => {
      usersService.findByEmail.mockRejectedValue(new Error('fail'));
      await expect(
        service.loginWithFirebaseToken(mockDecodedToken as any),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('loginWithGoogleToken', () => {
    const googlePayload = {
      email: 'test@alumnos.ucn.cl',
      name: 'Test User',
    };

    it('should login and return tokens and user', async () => {
      usersService.findByEmail.mockResolvedValue(mockUser);
      jwtService.generateAccessToken.mockResolvedValue('access-token');
      jwtService.generateRefreshToken.mockResolvedValue('refresh-token');
      const result = await service.loginWithGoogleToken(googlePayload as any);
      expect(usersService.findByEmail).toHaveBeenCalledWith(
        googlePayload.email,
      );
      expect(result).toHaveProperty('user');
      expect(result).toHaveProperty('accessToken', 'access-token');
      expect(result).toHaveProperty('refreshToken', 'refresh-token');
    });

    it('should register user if not found', async () => {
      usersService.findByEmail.mockResolvedValue(null);
      usersService.createUser.mockResolvedValue(mockUser);
      jwtService.generateAccessToken.mockResolvedValue('access-token');
      jwtService.generateRefreshToken.mockResolvedValue('refresh-token');
      const result = await service.loginWithGoogleToken(googlePayload as any);
      expect(usersService.createUser).toHaveBeenCalled();
      expect(result.user).toEqual(mockUser);
    });

    it('should throw UnauthorizedException on error', async () => {
      usersService.findByEmail.mockRejectedValue(new Error('fail'));
      await expect(
        service.loginWithGoogleToken(googlePayload as any),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('refreshToken', () => {
    it('should refresh and rotate tokens', async () => {
      jwtService.verifyAsync.mockResolvedValue({ sub: mockUser.id });
      usersService.findById.mockResolvedValue(mockUser);
      jwtService.generateAccessToken.mockResolvedValue('new-access');
      jwtService.generateRefreshToken.mockResolvedValue('new-refresh');
      const result = await service.refreshToken('refresh-token');
      expect(jwtService.verifyAsync).toHaveBeenCalled();
      expect(usersService.findById).toHaveBeenCalledWith(mockUser.id);
      expect(result).toHaveProperty('accessToken', 'new-access');
      expect(result).toHaveProperty('refreshToken', 'new-refresh');
      expect(result).toHaveProperty('user', mockUser);
    });

    it('should throw UnauthorizedException if user not found', async () => {
      jwtService.verifyAsync.mockResolvedValue({ sub: 'notfound' });
      usersService.findById.mockResolvedValue(null);
      await expect(service.refreshToken('refresh-token')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException on error', async () => {
      jwtService.verifyAsync.mockRejectedValue(new Error('fail'));
      await expect(service.refreshToken('refresh-token')).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('buildJwtPayload', () => {
    it('should build payload', () => {
      const payload = (service as any).buildJwtPayload(mockUser);
      expect(payload).toEqual({
        sub: mockUser.id,
        email: mockUser.email,
        role: mockUser.role,
      });
    });
  });
});
