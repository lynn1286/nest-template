import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import configurationYaml from './config/index';
import { TypeOrmModule } from '@nestjs/typeorm';
import { APP_FILTER, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core';
import { HttpExceptionFilter } from './core/filter/http.exception/http.exception.filter';
import { TransformInterceptor } from './core/interceptor/transform/transform.interceptor';
import { UserModule } from './core/modules/user/user.module';
import { ValidationPipe } from './core/pipes/validation/validation.pipe';
import { CacheModule } from './core/modules/cache/cache.module';
import { AuthModule } from './modules/auth/auth.module';
import { PermissionModule } from './core/modules/permission/permission.module';
import { RoleModule } from './core/modules/role/role.module';
import { ArticleModule } from './modules/article/article.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      cache: true,
      load: [configurationYaml],
      isGlobal: true,
    }),

    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        return configService.get('GLOBAL_CONFIG.db.mysql');
      },
    }),
    UserModule,
    CacheModule,
    AuthModule,
    PermissionModule,
    RoleModule,
    ArticleModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
    {
      provide: APP_PIPE,
      useClass: ValidationPipe,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformInterceptor,
    },
    AppService,
  ],
})
export class AppModule {}
