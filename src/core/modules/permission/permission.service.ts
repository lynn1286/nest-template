import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  CreatePermissionDto,
  CreatePermissionDtoArray,
} from './dto/create-permission.dto';
import { Permission } from './entities/permission.entity';
import { ErrorCodeEnum } from '@/common/enums/error.code.enum';

@Injectable()
export class PermissionService {
  constructor(
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
  ) {}

  /**
   * @description: 创建权限
   * @param {CreatePermissionDtoArray} CreatePermissionDtoArray
   * @return {*}
   */
  async create(createPermissionDtoArray: CreatePermissionDtoArray) {
    const savedEntities: CreatePermissionDto[] = [];
    const errorEntities: any[] = [];
    for (const createPermissionDto of createPermissionDtoArray.permissions) {
      const name = createPermissionDto.name;
      const existPermission = await this.permissionRepository.findOne({
        where: { name },
      });

      if (!existPermission) {
        const newEntity = this.permissionRepository.create(createPermissionDto);
        const savedEntity = await this.permissionRepository.save(newEntity);
        savedEntities.push(savedEntity);
      } else {
        errorEntities.push({
          msg: '权限已存在',
          code: ErrorCodeEnum.PERMISSSION_EXIST,
        });
      }
    }

    return {
      savedEntities,
      errorEntities,
    };
  }
}
