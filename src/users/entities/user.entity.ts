import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  DeleteDateColumn,
  UpdateDateColumn,
  CreateDateColumn,
} from 'typeorm';
import { UserRole } from '../../common/enums/user-role.enum';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({
    name: 'email',
    type: 'varchar',
    length: 255,
    unique: true,
    nullable: false,
    comment: 'Correo electrónico del usuario',
    transformer: {
      to: (value: string) => value.trim().toLowerCase(),
      from: (value: string) => value.trim().toLowerCase(),
    },
  })
  email: string;

  @Column({
    name: 'full_name',
    type: 'varchar',
    length: 255,
    nullable: false,
    comment: 'Nombre completo del usuario',
    transformer: {
      to: (value: string) => value.trim(),
      from: (value: string) => value.trim(),
    },
  })
  fullName: string;

  @Column({
    name: 'role',
    type: 'enum',
    enum: UserRole,
    default: UserRole.ESTUDIANTE,
    nullable: false,
    comment: 'Rol del usuario',
  })
  role: UserRole;

  @CreateDateColumn({
    name: 'created_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    comment: 'Fecha de creación del usuario',
  })
  createdAt: Date;

  @UpdateDateColumn({
    name: 'updated_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    onUpdate: 'CURRENT_TIMESTAMP',
    comment: 'Fecha de última actualización del usuario',
  })
  updatedAt: Date;

  @DeleteDateColumn({
    name: 'deleted_at',
    type: 'timestamp',
    nullable: true,
    default: null,
    comment: 'Fecha de eliminación del usuario',
  })
  deletedAt: Date;
}
