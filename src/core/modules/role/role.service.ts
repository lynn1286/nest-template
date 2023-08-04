import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { Role } from './entities/role.entity';
import { Permission } from '../permission/entities/permission.entity';
import { APIException } from '@/core/filter/http.exception/api.exception.filter';
import { ErrorCodeEnum } from '@/common/enums/error.code.enum';
import { CreateRoleDto } from '@/modules/auth/dto/create-role.dto';
import { UpdateRoleDto } from '@/modules/auth/dto/update-role.dto';

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

  /**
   * @description: 根据角色ID修改权限
   * @return {*}
   */
  async updateById(id: string, updateRoleDto: UpdateRoleDto) {
    const { name, permissionIds } = updateRoleDto;
    const role = await this.roleRepository.findOne({
      where: { id },
    });
    if (!role) {
      throw new APIException('角色不存在', ErrorCodeEnum.ROLE_NOT_EXIST);
    }

    if (name) {
      role.name = name;
      await this.roleRepository.save(role);
    }

    if (permissionIds) {
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
      role.permissions = existingPermissions;
      await this.roleRepository.save(role);
    }

    return '更新成功';
  }
}
