import {
  Inject,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { S3Service } from '../s3/s3.service';
import config from '../config/config';
import { ConfigType } from '@nestjs/config';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';

@Injectable()
export class VideoStorageService {
  constructor(
    @Inject('S3_CLIENT')
    private readonly s3Client: S3Client,
    @Inject(config.KEY)
    private readonly configService: ConfigType<typeof config>,
    private readonly s3Service: S3Service,
  ) {}

  async uploadFile(
    fileKey: string,
    file: Express.Multer.File,
  ): Promise<string> {
    return this.s3Service.uploadFile(fileKey, file.buffer, file.mimetype);
  }

  async uploadLargeFile(
    fileKey: string,
    file: Express.Multer.File,
  ): Promise<string> {
    return this.s3Service.uploadLargeFile(fileKey, file.buffer, file.mimetype);
  }

  async getFileStream(
    fileKey: string,
    start?: number,
    end?: number,
  ): Promise<any> {
    try {
      const params = {
        Bucket: this.configService.aws.s3.bucketName,
        Key: fileKey,
        Range:
          start !== undefined && end !== undefined
            ? `bytes=${start}-${end}`
            : undefined,
      };

      const command = new GetObjectCommand(params);
      const response = await this.s3Client.send(command);

      return response.Body; // ReadableStream
    } catch (error) {
      throw new InternalServerErrorException(
        'Error getting file stream from S3',
      );
    }
  }

  async getFile(fileKey: string): Promise<Buffer> {
    return this.s3Service.getFile(fileKey);
  }

  async deleteFile(fileKey: string): Promise<void> {
    return this.s3Service.deleteFile(fileKey);
  }
}
