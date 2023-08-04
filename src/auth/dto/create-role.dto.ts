import { IsArray, IsNumber, IsString, MaxLength } from 'class-validator';

export class CreateRoleDto {
  @IsString()
  @MaxLength(20)
  name: string;

  @IsArray()
  @IsNumber({}, { each: true })
  permissionIds: number[];
}
