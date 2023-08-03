import { PipeTransform, Injectable, ArgumentMetadata } from '@nestjs/common';
import { plainToClass } from 'class-transformer';
import { ValidationError, validate } from 'class-validator';
import { ErrorCodeEnum } from 'src/common/enums/error.code.enum';
import { APIException } from 'src/core/filter/http.exception/api.exception.filter';

@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  async transform(
    paramValue: any,
    { metatype: paramMetaType }: ArgumentMetadata,
  ) {
    if (!paramMetaType || !this.toValidate(paramMetaType)) {
      return paramValue;
    }
    const object = plainToClass(paramMetaType, paramValue);

    // 不允许传入DTO中未定义并且没有class-validator装饰器的参数,否则报错
    const errors = await validate(object, {
      whitelist: true,
      forbidNonWhitelisted: true,
    });
    const errorList: string[] = [];
    const errObjList: ValidationError[] = [...errors];

    do {
      const e = errObjList.shift();
      if (!e) {
        break;
      }
      if (e.constraints) {
        for (const item in e.constraints) {
          errorList.push(e.constraints[item]);
        }
      }
      if (e.children) {
        errObjList.push(...e.children);
      }
    } while (true);
    if (errorList.length > 0) {
      throw new APIException(
        '请求参数校验错误:' + errorList.join(),
        ErrorCodeEnum.QUERY_PARAM_INVALID_FAIL,
      );
    }
    return object;
  }

  private toValidate(paramMetatype: Function): boolean {
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(paramMetatype);
  }
}
