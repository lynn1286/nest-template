import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto } from '@/user/dto/create-user.dto';
import { UserService } from '@/user/user.service';
import { SigninDto } from './dto/signin.dto';
import encry from '@/common/utils/crypto.util';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  /**
   * @description: 注册用户
   * @param {CreateUserDto} createUserDto
   * @return {*}
   */
  async create(createUserDto: CreateUserDto) {
    return await this.userService.create(createUserDto);
  }

  /**
   * @description: 登陆
   * @param {SigninDto} signinDto
   * @return {*}
   */
  async signin(signinDto: SigninDto) {
    const { username, password } = signinDto;
    const user = await this.userService.findOne(username);

    if (user?.password !== encry(password, user.salt)) {
      throw new HttpException('密码错误', HttpStatus.UNAUTHORIZED);
    }

    // jwt 参数
    const payload = { username: user.username, sub: user.id };

    // 生成 token
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
