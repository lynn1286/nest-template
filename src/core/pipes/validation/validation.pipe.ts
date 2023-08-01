import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { plainToClass } from 'class-transformer';
import { validate } from 'class-validator';

@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  async transform(value: any, metadata: ArgumentMetadata) {
    if (!metadata.metatype || !this.toValidate(metadata.metatype)) {
      return value;
    }
    const object = plainToClass(metadata.metatype, value);
    const errors = await validate(object);
    if (errors.length > 0) {
      throw new BadRequestException(this.stringifyValidationErrors(errors));
    }
    return value;
  }

  private toValidate(metatype: any): boolean {
    const types: any[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }

  private stringifyValidationErrors(errors: any[]): string[] {
    const result: string[] = [];
    errors.forEach((error) => {
      Object.entries(error.constraints).forEach(([property, message]) => {
        result.push(`${error.property}: ${message}`);
      });
    });
    return result;
  }
}
