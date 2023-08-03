import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '@/core/modules/user/dto/create-user.dto';
import { SigninDto } from './dto/signin.dto';
import { Public } from '@/common/decorator/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @Public()
  async signup(@Body() createUserDto: CreateUserDto) {
    return await this.authService.create(createUserDto);
  }

  @Post('signin')
  @Public()
  async signin(@Body() signinDto: SigninDto) {
    return await this.authService.signin(signinDto);
  }
}
