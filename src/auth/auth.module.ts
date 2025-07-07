import { Module } from '@nestjs/common';
import { FirebaseModule } from '../firebase/firebase.module';
import { JwtModule } from '../jwt/jwt.module';
import { UsersModule } from '../users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { FirebaseAuthGuard } from './guards/firebase-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { SupportEmailGuard } from './guards/support-email.guard';

@Module({
  imports: [UsersModule, FirebaseModule, JwtModule],
  providers: [
    FirebaseAuthGuard,
    RolesGuard,
    AuthService,
    GoogleAuthGuard,
    SupportEmailGuard,
  ],
  controllers: [AuthController],
  exports: [FirebaseAuthGuard, RolesGuard, GoogleAuthGuard, SupportEmailGuard],
})
export class AuthModule {}
