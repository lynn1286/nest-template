import { Controller, Post, Body } from '@nestjs/common';
import { PermissionService } from './permission.service';
import { CreatePermissionDtoArray } from './dto/create-permission.dto';

@Controller('permission')
export class PermissionController {
  constructor(private readonly permissionService: PermissionService) {}

  @Post('create')
  create(@Body() createPermissionDtoArray: CreatePermissionDtoArray) {
    return this.permissionService.create(createPermissionDtoArray);
  }
}
