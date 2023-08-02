import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map, tap } from 'rxjs/operators';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';
import { Response, Request } from 'express';
import { Reflector } from '@nestjs/core';

export interface IResponse<T> {
  data: T;
}

/** 每次请求的记数器 */
let requestSeq = 0;

@Injectable()
export class TransformInterceptor implements NestInterceptor {
  private readonly logger = new Logger(TransformInterceptor.name);

  constructor(private reflector: Reflector) {}

  intercept(
    paramContext: ExecutionContext,
    paramNext: CallHandler,
  ): Observable<any> {
    /** 请求开始时间 */
    const start = Date.now();
    /** 当前环境 */
    const host = paramContext.switchToHttp();
    /** 请求对象 */
    const req = host.getRequest<Request>();
    /** 响应对象 */
    const res = host.getResponse<Response>();
    /** 当前计数 */
    const seq = requestSeq++;
    /** 当前URL */
    const url = req.url; // req.path;
    /** 当前URL */
    const urlInfo = `${req.method} ${url}`;

    this.logger.log(`Incoming request: [第${seq}次] ==> ${urlInfo}`);
    req['seq'] = seq;

    return paramNext
      .handle()
      .pipe(
        map((data) => {
          /* 这里拦截POST返回的statusCode，它默认返回是201, 这里改为200 */
          if (res.statusCode === HttpStatus.CREATED && req.method === 'POST') {
            res.statusCode = HttpStatus.OK;
          }

          return {
            /** 成功消息 */
            msg: '请求成功',
            /** 业务状态码 */
            code: ErrorCodeEnum.SUCCESS,
            /** http 状态码 */
            statusCode: res.statusCode,
            /** 请求的数据 */
            data,
          };
        }),
      )
      .pipe(
        // 这里打印请求处理完成的信息
        tap(() =>
          this.logger.log(
            `Response request: [第${seq}次] <== ${urlInfo} ${
              Date.now() - start
            } ms`,
          ),
        ),
      );
  }
}
