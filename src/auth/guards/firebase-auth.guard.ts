import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { UCN_EMAIL_REGEX } from '../../common/constants/ucn-email.regex';
import { FirebaseService } from '../../firebase/firebase.service';

const ucnRegex = UCN_EMAIL_REGEX;

@Injectable()
export class FirebaseAuthGuard implements CanActivate {
  private readonly logger = new Logger(FirebaseAuthGuard.name);

  /**
   * Guarda de autenticación para validar tokens de Firebase y correos institucionales UCN.
   * @param firebaseService Servicio de Firebase para verificar tokens.
   */
  constructor(private readonly firebaseService: FirebaseService) {}

  /**
   * Método que se ejecuta para verificar si la solicitud está autorizada.
   * Extrae el token del encabezado de autorización, lo verifica y valida el correo electrónico.
   * @param context Contexto de ejecución de la solicitud.
   * @returns Verdadero si la autenticación es exitosa, falso en caso contrario.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    try {
      this.logger.log(`Attempting authentication for ${req.method} ${req.url}`);
      
      const token = this.extractToken(req.headers.authorization);
      this.logger.log('Token extracted successfully');
      
      const decodedToken = await this.firebaseService.verifyIdToken(token);
      this.logger.log(`Token verified for email: ${decodedToken.email}`);
      
      this.validateInstitutionalEmail(decodedToken.email);
      this.logger.log(`Institutional email validated: ${decodedToken.email}`);
      
      req.firebaseDecoded = decodedToken;
      this.logger.log(`Authentication successful for: ${decodedToken.email}`);
      return true;
    } catch (err) {
      this.logger.error(`Authentication failed: ${err.message}`, err.stack);
      if (
        err instanceof UnauthorizedException ||
        err instanceof ForbiddenException
      ) {
        throw err;
      }
      throw new UnauthorizedException(`Authentication failed: ${err.message}`);
    }
  }

  /**
   * Extrae el token del encabezado de autorización.
   * @param authHeader Encabezado de autorización de la solicitud.
   * @returns El token extraído.
   * @throws UnauthorizedException si no se proporciona un token válido.
   */
  private extractToken(authHeader: string): string {
    if (!authHeader?.startsWith('Bearer ')) {
      this.logger.warn('No token provided in Authorization header');
      throw new UnauthorizedException('No token provided');
    }
    return authHeader.split(' ')[1];
  }
  

  /**
   * Valida que el correo electrónico proporcionado sea un correo institucional UCN.
   * @param email Correo electrónico a validar.
   * @throws ForbiddenException si el correo no es válido.
   */
  private validateInstitutionalEmail(email: string): void {
  if (!email) {
    this.logger.warn('No email provided in token');
    throw new ForbiddenException('No email found in authentication token');
  }
  
  // Excepción para el email de soporte
  if (email === 'soporte.videoteca@gmail.com') {
    this.logger.log(`Support email allowed: ${email}`);
    return;
  }
  
  if (!ucnRegex.test(email)) {
    this.logger.warn(`Invalid institutional email attempted: ${email}`);
    throw new ForbiddenException(
      `Solo se permiten correos institucionales UCN. Email recibido: ${email}. Formatos válidos: @ucn.cl, @alumnos.ucn.cl, @ce.ucn.cl`
    );
  }
  
  this.logger.log(`Valid UCN email: ${email}`);
}
}
