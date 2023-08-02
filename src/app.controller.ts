import { Controller, Get, HttpException, HttpStatus } from '@nestjs/common';
import { AppService } from './app.service';
import { ConfigService } from '@nestjs/config';
import { APIException } from './core/filter/http.exception/api.exception.filter';
import { ErrorCodeEnum } from './common/enums/error.code.enum';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly configService: ConfigService,
  ) {}

  @Get()
  getHello(): string {
    // throw new HttpException('禁止访问', HttpStatus.FORBIDDEN);

    // 自定义 Exception 返回业务异常
    throw new APIException('用户不存在', ErrorCodeEnum.USER_EXIST);
    return this.appService.getHello();
  }
}
