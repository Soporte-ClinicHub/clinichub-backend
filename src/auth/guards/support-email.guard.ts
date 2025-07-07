import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ForbiddenException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtService } from '../../jwt/jwt.service';
import { Request } from 'express';

@Injectable()
export class SupportEmailGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new ForbiddenException('No token provided');
    }
    const token = authHeader.split(' ')[1];
    try {
      const payload = await this.jwtService.verifyAsync(token);
      if (payload.email === 'soporte.videoteca@gmail.com') {
        return true;
      }
      throw new ForbiddenException('Solo soporte puede acceder');
    } catch {
      throw new ForbiddenException('Token inválido');
    }
  }
}
