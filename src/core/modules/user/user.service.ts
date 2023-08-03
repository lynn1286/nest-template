import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { In, Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { APIException } from 'src/core/filter/http.exception/api.exception.filter';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';
import { Role } from '../role/entities/role.entity';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
    @InjectRepository(Role) private readonly roleRepository: Repository<Role>,
  ) {}

  /**
   * @description: 查找用户
   * @param {string} username
   * @return {*}
   */
  async findOne(username: string) {
    const user = await this.userRepository.findOne({
      where: { username },
    });

    if (!user) throw new HttpException('用户不存在', HttpStatus.BAD_REQUEST);
    return user;
  }

  /**
   * @description: 注册用户
   * @param {CreateUserDto} createUserDto
   * @return {*}
   */
  async create(createUserDto: CreateUserDto) {
    const { username, password, roleIds } = createUserDto;
    const existUser = await this.userRepository.findOneBy({ username });

    // 业务查询异常
    if (existUser) {
      throw new APIException('用户已存在', ErrorCodeEnum.USER_EXIST);
    }

    try {
      // 查询数组 roleIds 对应所有 role 的实体
      const roles = await this.roleRepository.find({
        where: {
          id: In(roleIds),
        },
      });

      // 创建新用户，此时还未写入到数据库
      const newUser = await this.userRepository.create({
        username,
        password,
        roles,
      });
      // save 调用表示写入数据库
      await this.userRepository.save(newUser);
      return '注册成功';
    } catch (error) {
      // 服务器内部出错
      throw new HttpException(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * @description: 查询用户权限
   * @return {*}
   */
  async findPermissionNames(token: string, userInfo) {
    const user = await this.userRepository.findOne({
      where: { username: userInfo.username },
      relations: ['roles', 'roles.permissions'],
    });
    if (user) {
      const permissions = user.roles.flatMap((role) => role.permissions);
      const permissionNames = permissions.map((item) => item.name);
      return [...new Set(permissionNames)];
    } else {
      return [];
    }
  }
}
