import {
  ConflictException,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { UserRole } from '../common/enums/user-role.enum';
import { User } from './entities/user.entity';
import { UsersService } from './users.service';

describe('UsersService', () => {
  let service: UsersService;
  let usersRepository: any;

  beforeEach(async () => {
    usersRepository = {
      create: jest.fn(),
      save: jest.fn(),
      findOne: jest.fn(),
      find: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        { provide: getRepositoryToken(User), useValue: usersRepository },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createUser', () => {
    it('should create user', async () => {
      usersRepository.create.mockReturnValue({
        email: 'a@ucn.cl',
        fullName: 'Test User',
        role: UserRole.ESTUDIANTE,
      });
      usersRepository.save.mockResolvedValue({
        id: '1',
        email: 'a@ucn.cl',
        fullName: 'Test User',
        role: UserRole.ESTUDIANTE,
      });
      const result = await service.createUser({
        email: 'a@ucn.cl',
        fullName: 'Test User',
        role: UserRole.ESTUDIANTE,
      });
      expect(result).toEqual({
        id: '1',
        email: 'a@ucn.cl',
        fullName: 'Test User',
        role: UserRole.ESTUDIANTE,
      });
    });

    it('should throw ConflictException on duplicate', async () => {
      usersRepository.create.mockReturnValue({});
      usersRepository.save.mockRejectedValue({ code: '23505' });
      await expect(
        service.createUser({
          email: 'a@ucn.cl',
          fullName: 'Test User',
          role: UserRole.ESTUDIANTE,
        }),
      ).rejects.toThrow(ConflictException);
    });

    it('should throw InternalServerErrorException on invalid data', async () => {
      usersRepository.create.mockReturnValue({});
      usersRepository.save.mockRejectedValue([{ constraints: {} }]);
      await expect(
        service.createUser({
          email: 'a@ucn.cl',
          fullName: 'Test User',
          role: UserRole.ESTUDIANTE,
        }),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('findById', () => {
    it('should return user', async () => {
      usersRepository.findOne.mockResolvedValue({ id: '1' });
      const result = await service.findById('1');
      expect(result).toEqual({ id: '1' });
    });

    it('should throw NotFoundException if not found', async () => {
      usersRepository.findOne.mockResolvedValue(null);
      await expect(service.findById('2')).rejects.toThrow(NotFoundException);
    });
  });

  describe('findByEmail', () => {
    it('should return user', async () => {
      usersRepository.findOne.mockResolvedValue({ id: '1' });
      const result = await service.findByEmail('a@ucn.cl');
      expect(result).toEqual({ id: '1' });
    });

    it('should throw NotFoundException if not found', async () => {
      usersRepository.findOne.mockResolvedValue(null);
      await expect(service.findByEmail('b@ucn.cl')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('findAll', () => {
    it('should return all users', async () => {
      usersRepository.find.mockResolvedValue([{ id: '1' }]);
      const result = await service.findAll();
      expect(result).toEqual([{ id: '1' }]);
    });
  });

  describe('updateUser', () => {
    it('should update user', async () => {
      usersRepository.update.mockResolvedValue(undefined);
      service.findById = jest.fn().mockResolvedValue({ id: '1' });
      const result = await service.updateUser('1', { fullName: 'Test' });
      expect(result).toEqual({ id: '1' });
    });

    it('should throw InternalServerErrorException on invalid data', async () => {
      usersRepository.update.mockRejectedValue([{ constraints: {} }]);
      await expect(service.updateUser('1', {})).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('deleteUser', () => {
    it('should delete user', async () => {
      usersRepository.delete.mockResolvedValue(undefined);
      await expect(service.deleteUser('1')).resolves.toBeUndefined();
    });

    it('should throw InternalServerErrorException on error', async () => {
      usersRepository.delete.mockRejectedValue(new Error('fail'));
      await expect(service.deleteUser('1')).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });
});
