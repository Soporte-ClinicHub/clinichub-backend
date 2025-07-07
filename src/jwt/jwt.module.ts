import { Module } from '@nestjs/common';
import { JwtModule as NestJwtModule } from '@nestjs/jwt';
import { ConfigType } from '@nestjs/config';
import config from '../config/config';
import { ConfigModule } from '../config/config.module';
import { JwtService } from './jwt.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [
    UsersModule,
    NestJwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [config.KEY],
      useFactory: (configService: ConfigType<typeof config>) => {
        const { accessSecret, accessExpiresIn } = configService.jwt;
        return {
          secret: accessSecret,
          signOptions: { expiresIn: accessExpiresIn },
        };
      },
    }),
  ],
  exports: [JwtService, NestJwtModule, JwtStrategy],
  providers: [JwtService, JwtStrategy],
})
export class JwtModule {}
