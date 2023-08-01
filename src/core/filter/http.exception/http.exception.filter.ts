import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ApiException } from './api.exception.filter';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>(); // 获取express响应上下文
    const request = ctx.getRequest<Request>(); // 获取express请求上下文
    const status = exception.getStatus(); // 读取http状态码

    // 判断 exception 是否在 ApiException 原型链上
    if (exception instanceof ApiException) {
      response.status(status).json({
        code: exception.getErrorCode(),
        timestamp: new Date().toISOString(),
        path: request.url,
        msg: exception.getErrorMessage(),
        stack: exception.stack,
        error: exception.getResponse(),
      });
    } else {
      response.status(status).json({
        code: status,
        timestamp: new Date().toISOString(),
        path: request.url,
        msg: exception.message,
        stack: exception.stack,
        error: exception.getResponse(),
      });
    }
  }
}
