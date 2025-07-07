import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  async createUser(data: CreateUserDto): Promise<User> {
    try {
      const user = this.usersRepository.create(data);
      const savedUser = await this.usersRepository.save(user);
      return savedUser;
    } catch (error) {
      if (error.code === '23505') {
        throw new ConflictException(
          'El correo electrónico ya está registrado.',
        );
      }
      if (Array.isArray(error) && error[0]?.constraints) {
        throw new InternalServerErrorException('Datos de usuario inválidos.');
      }
      throw new InternalServerErrorException('Error al crear el usuario.');
    }
  }

  async findById(id: string): Promise<User> {
    try {
      const user = await this.usersRepository.findOne({ where: { id } });
      if (!user) throw new NotFoundException('Usuario no encontrado');
      return user;
    } catch (error) {
      throw new InternalServerErrorException(
        'Error al buscar el usuario por id.',
      );
    }
  }

  async findByEmail(email: string): Promise<User | null> {
    try {
      return await this.usersRepository.findOne({ where: { email } });
    } catch (error) {
      throw new InternalServerErrorException(
        'Error al buscar el usuario por email.',
      );
    }
  }

  async findAll(): Promise<User[]> {
    try {
      return await this.usersRepository.find();
    } catch (error) {
      throw new InternalServerErrorException('Error al listar los usuarios.');
    }
  }

  async updateUser(id: string, updateDto: UpdateUserDto): Promise<User> {
    try {
      await this.usersRepository.update(id, updateDto);
      return this.findById(id);
    } catch (error) {
      if (Array.isArray(error) && error[0]?.constraints) {
        throw new InternalServerErrorException('Datos de usuario inválidos.');
      }
      throw new InternalServerErrorException('Error al actualizar el usuario.');
    }
  }

  async deleteUser(id: string): Promise<User> {
    try {
      const user = await this.findById(id);
      const result = await this.usersRepository.delete(id);
      if (result.affected === 0) {
        throw new NotFoundException('Usuario no encontrado');
      }

      return user;
    } catch (error) {
      throw new InternalServerErrorException('Error al eliminar el usuario.');
    }
  }
}
