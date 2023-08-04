import {
  Body,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AppService } from './app.service';
import { ConfigService } from '@nestjs/config';
import { APIException } from './core/filter/http.exception/api.exception.filter';
import { ErrorCodeEnum } from './common/enums/error.code.enum';
import { AuthGuard } from './modules/auth/auth.guard';
import { Public } from './common/decorator/public.decorator';
import { Permissions } from './common/decorator/permissions.decorator';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly configService: ConfigService,
  ) {}

  @Get()
  @Public()
  getHello(): string {
    // throw new HttpException('禁止访问', HttpStatus.FORBIDDEN);

    // 自定义 Exception 返回业务异常
    // throw new APIException('用户不存在', ErrorCodeEnum.USER_EXIST);
    return this.appService.getHello();
  }

  @Post('test')
  @Permissions('permission/create', 'permission/read')
  test() {
    return this.appService.getHello();
  }
}
