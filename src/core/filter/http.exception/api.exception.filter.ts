import { HttpException, HttpStatus } from '@nestjs/common';
import { ApiCode } from 'src/common/enums/api.code.enum';

/**
 * @description: 自定义 Exception 增加业务状态码响应
 * @return {*}
 */
export class ApiException extends HttpException {
  private errorMessage: string;
  private errorCode: ApiCode;

  constructor(
    errorMessage: string,
    errorCode: ApiCode,
    statusCode: HttpStatus = HttpStatus.OK,
  ) {
    super(errorMessage, statusCode);
    this.errorMessage = errorMessage;
    this.errorCode = errorCode;
  }

  getErrorCode(): ApiCode {
    return this.errorCode;
  }

  getErrorMessage(): string {
    return this.errorMessage;
  }
}
