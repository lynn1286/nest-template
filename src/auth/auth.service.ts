import { Injectable } from '@nestjs/common';
import { CreateUserDto } from '@/core/modules/user/dto/create-user.dto';
import { UserService } from '@/core/modules/user/user.service';
import { SigninDto } from './dto/signin.dto';
import { PermissionService } from '@/core/modules/permission/permission.service';
import { CreatePermissionDtoArray } from './dto/create-permission.dto';
import { RoleService } from '@/core/modules/role/role.service';
import { CreateRoleDto } from './dto/create-role.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly permissionService: PermissionService,
    private readonly roleService: RoleService,
  ) {}

  /**
   * @description: 注册用户
   * @param {CreateUserDto} createUserDto
   * @return {*}
   */
  async signup(createUserDto: CreateUserDto) {
    return await this.userService.signup(createUserDto);
  }

  /**
   * @description: 登陆
   * @param {SigninDto} signinDto
   * @return {*}
   */
  async signin(signinDto: SigninDto) {
    return await this.userService.signin(signinDto);
  }

  /**
   * @description: 创建权限
   * @param {CreatePermissionDtoArray} createPermissionDtoArray
   * @return {*}
   */
  async createPermission(createPermissionDtoArray: CreatePermissionDtoArray) {
    return await this.permissionService.create(createPermissionDtoArray);
  }

  /**
   * @description: 创建角色
   * @param {CreateRoleDto} createRoleDto
   * @return {*}
   */
  async createRole(createRoleDto: CreateRoleDto) {
    return await this.roleService.create(createRoleDto);
  }
}
