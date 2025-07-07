import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiTags,
  ApiResponse as SwaggerApiResponse,
} from '@nestjs/swagger';
import { ApiResponse } from 'src/common/types/ApiResponse.interface';
import { FirebaseRequest } from 'src/common/types/FirebaseRequest.interface';
import { GoogleRequest } from 'src/common/types/GoogleRequest.interface';
import { RefreshTokenResponse } from 'src/common/types/RefreshTokenResponse.interface';
import { AuthService } from './auth.service';
import { LoginResponse } from './dto/login-response.dto';
import { FirebaseAuthGuard } from './guards/firebase-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RefreshTokenGuard } from './guards/refresh-token.guard';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(FirebaseAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @SwaggerApiResponse({ status: 200, description: 'Login exitoso.' })
  @Post('login')
  async login(
    @Req() req: FirebaseRequest,
  ): Promise<ApiResponse<LoginResponse>> {
    const decodedToken = req.firebaseDecoded;
    const { user, accessToken, refreshToken } =
      await this.authService.loginWithFirebaseToken(decodedToken);
    return {
      statusCode: HttpStatus.OK,
      message: 'Login exitoso',
      data: {
        user,
        accessToken,
        refreshToken,
      },
    };
  }

  @UseGuards(GoogleAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @SwaggerApiResponse({ status: 200, description: 'Login Google exitoso.' })
  @Post('login-google')
  async loginGoogle(
    @Req() req: GoogleRequest,
  ): Promise<ApiResponse<LoginResponse>> {
    try {
      const decodedToken = req.googleDecoded;
      const { user, accessToken, refreshToken } =
        await this.authService.loginWithGoogleToken(decodedToken);
      return {
        statusCode: HttpStatus.OK,
        message: 'Login Google exitoso',
        data: {
          user,
          accessToken,
          refreshToken,
        },
      };
    } catch (error) {
      return {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: 'Error al iniciar sesión con Google',
        data: null,
      };
    }
  }

  @UseGuards(RefreshTokenGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @SwaggerApiResponse({ status: 200, description: 'Token refrescado.' })
  async refreshTokens(
    @Body() refreshToken: string,
  ): Promise<ApiResponse<RefreshTokenResponse>> {
    try {
      const { newAccessToken, newRefreshToken } =
        await this.authService.refreshToken(refreshToken);
      return {
        statusCode: HttpStatus.OK,
        message: 'Tokens refrescados exitosamente',
        data: { newAccessToken, newRefreshToken },
      };
    } catch (error) {
      if (error.statusCode === HttpStatus.UNAUTHORIZED) {
        if (error.name === 'TokenExpiredError') {
          return {
            statusCode: HttpStatus.UNAUTHORIZED,
            message: 'Refresh token expirado',
            data: null,
          };
        }
      }
      return {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: 'Error al refrescar tokens',
        data: null,
      };
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('validate')
  validateToken(): ApiResponse<boolean> {
    return {
      statusCode: HttpStatus.OK,
      message: 'Token válido',
      data: true,
    };
  }
}
