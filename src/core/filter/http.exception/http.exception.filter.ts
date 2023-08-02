import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { APIException } from './api.exception.filter';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(paramException: HttpException, paramHost: ArgumentsHost) {
    const ctx = paramHost.switchToHttp();
    const response = ctx.getResponse() as Response;
    const request = ctx.getRequest() as Request;

    const message = paramException.message;

    let retCode = ErrorCodeEnum.FAIL;
    let status = HttpStatus.OK;

    if (paramException instanceof APIException) {
      retCode = (paramException as APIException).getErrorCode();
    } else if (paramException instanceof HttpException) {
      status = (paramException as HttpException).getStatus();
    } else {
      status = HttpStatus.INTERNAL_SERVER_ERROR;
    }

    const errorResponse = {
      /** 错误消息 */
      msg: message,
      /** 业务状态码 */
      code: retCode,
      /** http 状态码 */
      statusCode: status,
      /** 当前请求路由 */
      url: request.originalUrl,
    };

    // 设置返回的状态码、请求头、发送错误信息
    response.status(HttpStatus.OK);
    response.header('Content-Type', 'application/json; charset=utf-8');
    response.send(errorResponse);
  }
}
