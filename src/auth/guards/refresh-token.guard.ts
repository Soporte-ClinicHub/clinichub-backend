import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  Inject,
} from '@nestjs/common';
import { JwtService } from '../../jwt/jwt.service';
import { ConfigType } from '@nestjs/config';
import config from '../../config/config';

@Injectable()
export class RefreshTokenGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(config.KEY)
    private readonly configService: ConfigType<typeof config>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const refreshToken = req.body.refreshToken || req.query.refreshToken;
    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token provided');
    }
    try {
      await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.jwt.refreshSecret,
      });
      return true;
    } catch {
      throw new UnauthorizedException('Refresh token inválido o expirado');
    }
  }
}
