import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: any;

  const mockUser = {
    id: '1',
    email: 'test@ucn.cl',
    fullName: 'Test',
    role: 'ESTUDIANTE',
  };
  const mockTokens = {
    accessToken: 'access',
    refreshToken: 'refresh',
    user: mockUser,
  };

  beforeEach(async () => {
    authService = {
      loginWithFirebaseToken: jest.fn(),
      loginWithGoogleToken: jest.fn(),
      refreshToken: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [{ provide: AuthService, useValue: authService }],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('login', () => {
    it('should return login response', async () => {
      authService.loginWithFirebaseToken.mockResolvedValue(mockTokens);
      const req = { firebaseDecoded: { uid: 'abc' } };
      const result = await controller.login(req);
      expect(result).toHaveProperty('message', 'Login exitoso');
      expect(result.data).toHaveProperty('user');
      expect(authService.loginWithFirebaseToken).toHaveBeenCalled();
    });
  });

  describe('refresh', () => {
    it('should return refresh response', async () => {
      authService.refreshToken.mockResolvedValue({
        accessToken: 'access',
        user: mockUser,
      });
      const req = { body: { refreshToken: 'refresh' } };
      const result = await controller.refresh(req);
      expect(result).toHaveProperty('message', 'Token refrescado');
      expect(result.data).toHaveProperty('user');
      expect(authService.refreshToken).toHaveBeenCalledWith('refresh');
    });
  });

  describe('loginGoogle', () => {
    it('should return login google response', async () => {
      authService.loginWithGoogleToken.mockResolvedValue(mockTokens);
      const req = { googleDecoded: { sub: 'abc' } };
      const result = await controller.loginGoogle(req);
      expect(result).toHaveProperty('message', 'Login Google exitoso');
      expect(result.data).toHaveProperty('user');
      expect(authService.loginWithGoogleToken).toHaveBeenCalled();
    });
  });

  describe('refreshGoogle', () => {
    it('should return refresh google response', async () => {
      authService.refreshToken.mockResolvedValue({
        accessToken: 'access',
        user: mockUser,
      });
      const req = { body: { refreshToken: 'refresh' } };
      const result = await controller.refreshGoogle(req);
      expect(result).toHaveProperty('message', 'Token Google refrescado');
      expect(result.data).toHaveProperty('user');
      expect(authService.refreshToken).toHaveBeenCalledWith('refresh');
    });
  });
});
