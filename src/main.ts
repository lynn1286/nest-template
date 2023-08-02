import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';

const logger = new Logger('Bootstrap');

logger.log(`程序开始启动, 当前环境： ${process.env.NODE_ENV ?? 'local'}`);

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const configService = app.get(ConfigService);

  const http = configService.get('GLOBAL_CONFIG.http') as {
    host: string;
    port: number;
  };

  await app.listen(http.port);
  logger.log(`应用程序已启动并侦听端口: ${http.port}`);
}

bootstrap();
