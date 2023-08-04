import { Module } from '@nestjs/common';
import { CacheService } from './cache.service';
import { createClient } from 'redis';
import { ConfigService } from '@nestjs/config';

@Module({
  providers: [
    CacheService,
    {
      provide: 'REDIS_CLIENT',
      inject: [ConfigService],
      async useFactory(configService: ConfigService) {
        const socket = configService.get('GLOBAL_CONFIG.db.redis');
        const client = createClient({
          socket,
        });
        await client.connect();
        return client;
      },
    },
  ],
  exports: [CacheService],
})
export class CacheModule {}
