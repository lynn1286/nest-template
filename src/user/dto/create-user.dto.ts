import { IsNotEmpty } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty({ message: ' $property不能为空' })
  username: string;

  @IsNotEmpty({ message: ' $property不能为空' })
  password: string;
}
