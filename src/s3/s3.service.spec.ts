import { Test, TestingModule } from '@nestjs/testing';
import { S3Service } from './s3.service';

describe('S3Service', () => {
  let service: S3Service;
  let s3Client: any;
  let configService: any;

  beforeEach(async () => {
    configService = {
      aws: {
        s3: { bucketName: 'bucket' },
        region: 'us-east-1',
        accessKeyId: 'key',
        secretAccessKey: 'secret',
      },
    };
    s3Client = {
      send: jest.fn(),
    };
    service = new S3Service(configService, s3Client);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should upload file', async () => {
    s3Client.send.mockResolvedValue({});
    const url = await service.uploadFile('key', Buffer.from('a'), 'type');
    expect(url).toContain('amazonaws.com');
  });

  it('should upload large file', async () => {
    s3Client.send
      .mockResolvedValueOnce({ UploadId: 'uploadid' })
      .mockResolvedValueOnce({ ETag: 'etag1' })
      .mockResolvedValueOnce({ ETag: 'etag2' })
      .mockResolvedValueOnce({});
    const url = await service.uploadLargeFile(
      'key',
      Buffer.alloc(10 * 1024 * 1024),
      'type',
      5 * 1024 * 1024,
    );
    expect(url).toContain('amazonaws.com');
  });

  it('should get file', async () => {
    const body = {
      transformToByteArray: jest.fn().mockResolvedValue([1, 2, 3]),
    };
    s3Client.send.mockResolvedValue({ Body: body });
    const buf = await service.getFile('key');
    expect(Buffer.isBuffer(buf)).toBe(true);
  });

  it('should delete file', async () => {
    s3Client.send.mockResolvedValue({});
    await expect(service.deleteFile('key')).resolves.toBeUndefined();
  });

  it('should get file url', () => {
    const url = service.getFileUrl('key');
    expect(url).toContain('amazonaws.com');
  });
});
