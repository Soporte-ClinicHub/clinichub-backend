import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { OAuth2Client } from 'google-auth-library';
import { UCN_EMAIL_REGEX } from '../../common/constants/ucn-email.regex';

const ucnRegex = UCN_EMAIL_REGEX;

@Injectable()
export class GoogleAuthGuard implements CanActivate {
  private readonly logger = new Logger(GoogleAuthGuard.name);
  private readonly client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    try {
      const token = this.extractToken(req.headers.authorization);
      const ticket = await this.client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      this.validateInstitutionalEmail(payload.email);
      req.googleDecoded = payload;
      this.logger.log(`Token Google Cloud válido para: ${payload.email}`);
      return true;
    } catch (err) {
      this.logger.error('Error en autenticación GoogleAuthGuard', err);
      if (
        err instanceof UnauthorizedException ||
        err instanceof ForbiddenException
      )
        throw err;
      throw new UnauthorizedException('Invalid Google token');
    }
  }

  private extractToken(authHeader: string): string {
    if (!authHeader?.startsWith('Bearer ')) {
      this.logger.warn('No token provided in Authorization header');
      throw new UnauthorizedException('No token provided');
    }
    return authHeader.split(' ')[1];
  }

  private validateInstitutionalEmail(email: string): void {
    if (!email || !ucnRegex.test(email)) {
      throw new ForbiddenException(
        'Solo se permiten correos institucionales UCN.',
      );
    }
  }
}
