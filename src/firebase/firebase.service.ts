import { Injectable, Inject, Logger } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ConfigType } from '@nestjs/config';
import config from '../config/config';

@Injectable()
export class FirebaseService {
  private readonly firebaseApp: admin.app.App;
  private readonly logger = new Logger(FirebaseService.name);

  constructor(
    @Inject(config.KEY)
    private readonly configService: ConfigType<typeof config>,
  ) {
    const firebaseConfig = this.configService.firebase;
    
    // Validate Firebase configuration
    if (!firebaseConfig.projectId || !firebaseConfig.privateKey || !firebaseConfig.clientEmail) {
      this.logger.error('Firebase configuration is incomplete. Please check your environment variables:');
      this.logger.error('- FIREBASE_PROJECT_ID');
      this.logger.error('- FIREBASE_PRIVATE_KEY');
      this.logger.error('- FIREBASE_CLIENT_EMAIL');
      throw new Error('Firebase configuration is incomplete');
    }

    if (!admin.apps.length) {
      this.firebaseApp = admin.initializeApp({
        credential: admin.credential.cert({
          projectId: firebaseConfig.projectId,
          privateKey: firebaseConfig.privateKey?.replace(/\\n/g, '\n'),
          clientEmail: firebaseConfig.clientEmail,
        }),
      });
      this.logger.log('Firebase Admin SDK initialized successfully');
    } else {
      this.firebaseApp = admin.app();
    }
  }

  async verifyIdToken(token: string): Promise<admin.auth.DecodedIdToken> {
    try {
      const decodedToken = await this.firebaseApp.auth().verifyIdToken(token);
      this.logger.log(`Token verified successfully for user: ${decodedToken.email}`);
      return decodedToken;
    } catch (error) {
      this.logger.error('Error verifying Firebase token:', error.message);
      throw error;
    }
  }
}
