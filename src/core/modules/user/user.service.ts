import { HttpException, HttpStatus, Inject, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { APIException } from 'src/core/filter/http.exception/api.exception.filter';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';
import { Role } from '../role/entities/role.entity';
import { SigninDto } from '@/auth/dto/signin.dto';
import encry from '@/common/utils/crypto.util';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
    @InjectRepository(Role) private readonly roleRepository: Repository<Role>,
    private readonly jwtService: JwtService,
  ) {}

  /**
   * @description: 查找用户
   * @param {string} username
   * @return {*}
   */
  async signin(signinDto: SigninDto) {
    const { username, password } = signinDto;
    const user = await this.userRepository.findOne({
      where: { username },
    });

    if (!user) throw new HttpException('用户不存在', HttpStatus.BAD_REQUEST);

    if (user?.password !== encry(password, user.salt)) {
      throw new HttpException('密码错误', HttpStatus.UNAUTHORIZED);
    }
    const payload = { username: user.username, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  /**
   * @description: 注册用户
   * @param {CreateUserDto} createUserDto
   * @return {*}
   */
  async signup(createUserDto: CreateUserDto) {
    // 查询是否存在用户
    const existUser = await this.userRepository.findOneBy({
      username: createUserDto.username,
    });

    if (existUser) {
      throw new APIException('用户已存在', ErrorCodeEnum.USER_EXIST);
    }

    try {
      const newUser = await this.userRepository.create(createUserDto);
      await this.userRepository.save(newUser);
      return '注册成功';
    } catch (error) {
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
