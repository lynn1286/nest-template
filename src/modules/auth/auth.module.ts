import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserModule } from '@/core/modules/user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from './auth.guard';
import { PermissionModule } from '@/core/modules/permission/permission.module';
import { RoleModule } from '@/core/modules/role/role.module';

@Module({
  imports: [
    UserModule,
    PermissionModule,
    RoleModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      global: true,
      useFactory: (configService: ConfigService) => {
        return {
          secret: configService.get('GLOBAL_CONFIG.secret.jwt_secret'),
          signOptions: {
            expiresIn: '3600s',
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    {
      provide: APP_GUARD,
      useClass: AuthGuard, // 全局守卫
    },
  ],
})
export class AuthModule {}
