import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { APIException } from 'src/core/filter/http.exception/api.exception.filter';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
  ) {}

  /**
   * @description: 注册用户
   * @param {CreateUserDto} createUserDto
   * @return {*}
   */
  async create(createUserDto: CreateUserDto) {
    const { username } = createUserDto;
    const existUser = await this.userRepository.findOneBy({ username });

    // 业务查询异常
    if (existUser)
      throw new APIException('用户已存在', ErrorCodeEnum.USER_EXIST);

    try {
      // 创建新用户，此时还未写入到数据库
      const newUser = await this.userRepository.create(createUserDto);

      // save 调用表示写入数据库
      return await this.userRepository.save(newUser);
    } catch (error) {
      // 服务器内部出错
      throw new HttpException(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
