import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { Role } from './entities/role.entity';
import { Permission } from '../permission/entities/permission.entity';
import { APIException } from '@/core/filter/http.exception/api.exception.filter';
import { ErrorCodeEnum } from '@/common/enums/error.code.enum';
import { CreateRoleDto } from '@/modules/auth/dto/create-role.dto';

@Injectable()
export class RoleService {
  constructor(
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
  ) {}

  /**
   * @description: 创建角色
   * @param {CreateRoleDto} createRoleDto
   * @return {*}
   */
  async create(createRoleDto: CreateRoleDto) {
    const { permissionIds, name } = createRoleDto;

    // 不允许乱传不存在的权限 id
    const existingPermissions = await this.permissionRepository.find({
      where: {
        id: In(permissionIds),
      },
    });

    const existingPermissionIds = existingPermissions.map(
      (permission) => permission.id,
    );

    const nonExistingPermissionIds = permissionIds.filter(
      (id) => !existingPermissionIds.includes(id as unknown as string),
    );

    if (nonExistingPermissionIds.length > 0) {
      throw new APIException(
        `未找到权限 ID: ${nonExistingPermissionIds.join(', ')}`,
        ErrorCodeEnum.PERMISSION_NOT_FOUND,
      );
    }

    const existRole = await this.roleRepository.findOne({
      where: { name },
    });

    if (existRole) {
      throw new APIException('角色已存在', ErrorCodeEnum.ROLE_EXIST);
    }

    return this.roleRepository.save({ permissions: existingPermissions, name });
  }
}
