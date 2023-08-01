import { Controller, Get, HttpException, HttpStatus } from '@nestjs/common';
import { AppService } from './app.service';
import { ConfigService } from '@nestjs/config';
import { ApiException } from './core/filter/http.exception/api.exception.filter';
import { ApiCode } from './common/enums/api.code.enum';

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
    throw new ApiException('用户不存在', ApiCode.USER_EXIST);
    return this.appService.getHello();
  }
}
