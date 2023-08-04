import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  @Inject()
  private jwtService: JwtService;

  @Inject()
  private configService: ConfigService;

  @Inject()
  private reflector: Reflector;

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 支持在 controller 或者 handler 上使用装饰器
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      // 即将调用的方法
      context.getHandler(),
      // controller 类型
      context.getClass(),
    ]);

    // 不需要鉴权的接口
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      this.logger.log(`非法访问: ${request.ip}`);
      throw new HttpException('禁止访问,请联系管理员', HttpStatus.FORBIDDEN);
    }

    try {
      // 校验 token
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get('GLOBAL_CONFIG.secret.jwt_secret'),
      });
      request['user'] = payload;
    } catch {
      this.logger.log(`token校验失败: ${request.ip}`);
      throw new HttpException(
        'token校验失败,请确认token是否有效',
        HttpStatus.FORBIDDEN,
      );
    }

    return true;
  }

  /**
   * @description: 解析获取token
   * @param {Request} request
   * @return {*}
   */
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
