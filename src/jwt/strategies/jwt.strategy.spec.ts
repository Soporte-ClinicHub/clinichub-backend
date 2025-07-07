import { JwtStrategy } from './jwt.strategy';
import { UnauthorizedException } from '@nestjs/common';

describe('JwtStrategy', () => {
  let strategy: JwtStrategy;
  let usersService: any;

  beforeEach(() => {
    usersService = {
      findById: jest.fn(),
    };
    strategy = new JwtStrategy(usersService, {
      get: jest.fn(() => 'secret'),
    } as any);
  });

  it('should be defined', () => {
    expect(strategy).toBeDefined();
  });

  it('should validate and return user', async () => {
    const user = { id: '1', email: 'a@ucn.cl' };
    usersService.findById.mockResolvedValue(user);
    const result = await strategy.validate({ sub: '1' });
    expect(result).toEqual(user);
  });

  it('should throw UnauthorizedException if user not found', async () => {
    usersService.findById.mockResolvedValue(null);
    await expect(strategy.validate({ sub: '2' })).rejects.toThrow(
      UnauthorizedException,
    );
  });
});
