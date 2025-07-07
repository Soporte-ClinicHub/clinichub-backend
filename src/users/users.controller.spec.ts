import { Test, TestingModule } from '@nestjs/testing';
import { UserRole } from '../common/enums/user-role.enum';
import { CreateUserDto } from './dto/create-user.dto';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

describe('UsersController', () => {
  let controller: UsersController;
  let service: any;

  const mockUser = { id: '1', email: 'test@ucn.cl', fullName: 'Test' };

  beforeEach(async () => {
    service = {
      findAll: jest.fn(),
      findById: jest.fn(),
      createUser: jest.fn(),
      updateUser: jest.fn(),
      deleteUser: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [{ provide: UsersService, useValue: service }],
    }).compile();

    controller = module.get<UsersController>(UsersController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should get all users', async () => {
    service.findAll.mockResolvedValue([mockUser]);
    const result = await controller.findAll();
    expect(result).toEqual([mockUser]);
  });

  it('should get user by id', async () => {
    service.findById.mockResolvedValue(mockUser);
    const result = await controller.findOne('1');
    expect(result).toEqual(mockUser);
  });

  it('should create user', async () => {
    const mockUserDto: CreateUserDto = {
      email: 'correo.institucional@alumnos.ucn.cl',
      fullName: 'Test',
      role: UserRole.ESTUDIANTE,
    };
    service.createUser.mockResolvedValue(mockUser);
    const result = await controller.create(mockUserDto);
    expect(result).toEqual(mockUser);
  });

  it('should update user', async () => {
    service.updateUser.mockResolvedValue(mockUser);
    const result = await controller.update('1', { fullName: 'Updated' });
    expect(result).toEqual(mockUser);
  });

  it('should delete user', async () => {
    service.deleteUser.mockResolvedValue(undefined);
    const result = await controller.remove('1');
    expect(result).toBeUndefined();
  });

  it('should return user from getProfile', () => {
    const req = { user: mockUser };
    expect(controller.getProfile(req)).toEqual(mockUser);
  });
});
