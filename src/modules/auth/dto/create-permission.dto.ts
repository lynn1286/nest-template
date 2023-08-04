import { Type } from 'class-transformer';
import {
  ArrayMinSize,
  ArrayNotEmpty,
  IsArray,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';

export class CreatePermissionDto {
  @IsString()
  @MaxLength(50)
  @IsNotEmpty()
  name: string;

  @IsString()
  @MaxLength(50)
  @IsOptional()
  desc: string;
}

export class CreatePermissionDtoArray {
  @IsArray()
  @ArrayNotEmpty()
  @ArrayMinSize(1)
  @ValidateNested({ each: true }) // 为每个元素启用嵌套验证
  @Type(() => CreatePermissionDto) // 指定嵌套对象的类类型
  permissions: CreatePermissionDto[];
}
