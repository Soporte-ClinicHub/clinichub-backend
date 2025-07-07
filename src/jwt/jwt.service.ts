import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService as NestJwtService } from '@nestjs/jwt';
import config from '../config/config';

@Injectable()
export class JwtService {
  constructor(
    private readonly nestJwtService: NestJwtService,
    @Inject(config.KEY)
    private readonly configService: ConfigType<typeof config>,
  ) {}

  async signAsync(payload: any, options?: any): Promise<string> {
    return this.nestJwtService.signAsync(payload, options);
  }

  async verifyAsync(token: string, options?: any): Promise<any> {
    return this.nestJwtService.verifyAsync(token, options);
  }

  sign(payload: any, options?: any): string {
    return this.nestJwtService.sign(payload, options);
  }

  verify(token: string, options?: any): any {
    return this.nestJwtService.verify(token, options);
  }

  decode(token: string, options?: any): any {
    return this.nestJwtService.decode(token, options);
  }

  // Generate access token
  async generateAccessToken(payload: any): Promise<string> {
    return this.nestJwtService.signAsync(payload);
  }

  // Generate refresh token
  async generateRefreshToken(payload: any): Promise<string> {
    return this.nestJwtService.signAsync(payload, {
      secret: this.configService.jwt.refreshSecret,
      expiresIn: this.configService.jwt.refreshExpiresIn,
    });
  }
}
