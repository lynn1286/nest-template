import { Module } from '@nestjs/common';
import { PermissionService } from './permission.service';
import { PermissionController } from './permission.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Permission } from './entities/permission.entity';
import { APP_GUARD } from '@nestjs/core';
import { PermissionGuard } from './permission.guard';
import { UserModule } from '../user/user.module';

@Module({
  imports: [UserModule, TypeOrmModule.forFeature([Permission])],
  controllers: [PermissionController],
  providers: [
    PermissionService,
    {
      provide: APP_GUARD,
      useClass: PermissionGuard,
    },
  ],
})
export class PermissionModule {}
