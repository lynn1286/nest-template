import { Controller, Post, Body, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '@/core/modules/user/dto/create-user.dto';
import { SigninDto } from './dto/signin.dto';
import { Public } from '@/common/decorator/public.decorator';
import { CreatePermissionDtoArray } from './dto/create-permission.dto';
import { CreateRoleDto } from './dto/create-role.dto';
import { Permissions } from '@/common/decorator/permissions.decorator';
import { UpdateRoleDto } from './dto/update-role.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @Public()
  async signup(@Body() createUserDto: CreateUserDto) {
    return await this.authService.signup(createUserDto);
  }

  @Post('signin')
  @Public()
  async signin(@Body() signinDto: SigninDto) {
    return await this.authService.signin(signinDto);
  }

  @Post('createPermission')
  @Permissions('auth/createPermission')
  createPermission(@Body() createPermissionDtoArray: CreatePermissionDtoArray) {
    this.authService.createPermission(createPermissionDtoArray);
  }

  @Post('createRole')
  @Permissions('auth/createRole')
  createRole(@Body() createRoleDto: CreateRoleDto) {
    return this.authService.createRole(createRoleDto);
  }

  @Post('updateRole/:id')
  @Permissions('auth/updateRole')
  updateRole(@Param('id') id: string, @Body() updateRoleDto: UpdateRoleDto) {
    return this.authService.updateRole(id, updateRoleDto);
  }
}
