import { IsNotEmpty, IsOptional, IsString, Length } from 'class-validator';

export class CreateUserDto {
  @Length(3, 30, { message: '$property最小3个字符,最大30个字符' })
  @IsNotEmpty({ message: '$property不能为空' })
  @IsString()
  username: string;

  @IsOptional() // 使用 IsOptional 装饰器来将字段设置为可选
  @IsString()
  @Length(3, 30, { message: '$property最小3个字符,最大30个字符' })
  nickname: string;

  @IsNotEmpty({ message: '$property不能为空' })
  @IsString()
  password: string;

  @IsOptional()
  @IsString()
  avatar: string;

  @IsOptional()
  @IsString()
  email: string;
}
