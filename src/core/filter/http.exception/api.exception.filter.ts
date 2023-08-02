import { HttpException, HttpStatus } from '@nestjs/common';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';

/**
 * @description: 自定义 Exception 增加业务状态码响应
 * @return {*}
 */
export class APIException extends HttpException {
  private errorMessage: string;
  private errorCode: ErrorCodeEnum;

  constructor(
    errorMessage: string,
    errorCode: ErrorCodeEnum,
    statusCode: HttpStatus = HttpStatus.OK,
  ) {
    super(errorMessage, statusCode);
    this.errorMessage = errorMessage;
    this.errorCode = errorCode;
  }

  getErrorCode(): ErrorCodeEnum {
    return this.errorCode;
  }

  getErrorMessage(): string {
    return this.errorMessage;
  }
}
